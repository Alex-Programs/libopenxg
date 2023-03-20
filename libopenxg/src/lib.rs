use reqwest;
use std::collections::hash_map::HashMap;
use std::fmt;
use std::time::SystemTime;

pub static DEFAULT_UA_SUFFIX: &str = "(Via libopenxg v0.9.0; Rust Reqwest; OS not shared; https://github.com/Alex-Programs/libopenxg)";

/// Request mode is an enum of the possible "modes" the firewall can take. I don't know why it's 191 or 192.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RequestMode {
    Login = 191,
    KeepAlive = 192,
}

/// Implement Display so .to_string() works; the firewall takes mode as a string.
impl fmt::Display for RequestMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RequestMode::Login => write!(f, "191"),
            RequestMode::KeepAlive => write!(f, "192"),
        }
    }
}

/// Use this to build the client used in later requests.
pub fn generate_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("Failed to create client")
}

/// Internal function for building the request body.
fn build_req<'a>(username: &String, password: Option<&String>, mode: RequestMode) -> HashMap<&'a str, String> {
    let a: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

    let mut data: HashMap<&str, String> = HashMap::new();

    data.insert("mode", mode.to_string());
    data.insert("a", a.to_string());
    data.insert("producttype", "0".to_string());
    data.insert("username", username.to_string());

    if mode == RequestMode::Login {
        if let Some(password) = password {
            data.insert("password", password.to_string());
        } else {
            panic!("Password is required for login");
        }
    }

    data
}

/// Login to the firewall.
pub fn login(url: &String, username: &String, password: &String, user_agent: &String, client: &reqwest::blocking::Client) -> Result<(), String> {
    let data = build_req(username, Some(password), RequestMode::Login);

    let response = client.post(format!("{}/login.xml", url).as_str())
        .form(&data)
        .header("User-Agent", user_agent)
        .send();

    match response {
        Ok(response) => {
            if response.status().is_success() {
                Ok(())
            } else {
                Err(format!("Login failed with status code {}", response.status()))
            }
        }
        Err(err) => {
            Err(format!("Login failed with error {}", err))
        }
    }
}

/// Keep the firewall session alive. Needed about once every two minutes, I recommend a 90 second timer.
pub fn keepalive(url: &String, username: &String, user_agent: &String, client: &reqwest::blocking::Client) -> Result<(), String> {
    let data = build_req(username, None,RequestMode::KeepAlive);

    // yes it's a get
    let response = client.get(format!("{}/live", &url).as_str())
        // yes params. yes it's inconsistent. yes it's stupid
        .query(&data)
        .header("User-Agent", user_agent)
        .send();

    match response {
        Ok(response) => {
            if response.status().is_success() {
                Ok(())
            } else {
                Err(format!("Keepalive failed with status code {}", response.status()))
            }
        }
        Err(err) => {
            Err(format!("Keepalive failed with error {}", err))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    pub fn test_login() {
        let client = generate_client();
        let url = "http://127.0.0.1:8090".to_string();
        let username = "admin".to_string();
        let password = "adminpwd".to_string();
        let user_agent = "user-agent".to_string();

        assert!(login(&url, &username, &password, &user_agent, &client).is_ok());
    }

    #[test]
    pub fn test_keepalive() {
        test_login();

        let client = generate_client();

        let url = "http://127.0.0.1:8090".to_string();
        let username = "admin".to_string();
        let user_agent = "user-agent".to_string();

        assert!(keepalive(&url, &username, &user_agent, &client).is_ok());
    }
}