from flask import Flask, request
import time

app = Flask(__name__)


@app.route("/login.xml", methods=["POST"])
def login():
    data = request.form

    print(request.form)
    print(data["mode"])
    print(data["a"])
    print(data["producttype"])

    print(request.headers.get("User-Agent"))

    if data["mode"] == "191" and float(data["a"]) > time.time() - 10 and float(data["a"]) < time.time() + 10 and data[
        "producttype"] == "0":
        if data["username"] == "admin" and data["password"] == "adminpwd":
            print("Valid login")
            return "You are signed in as {username}"
        else:
            print("Invalid login")
            return "No Access", 401

    return "Bad Request", 400

@app.route("/live", methods=["GET"])
def keepalive():
    data = request.args # args for /live

    print(data)
    print(data["mode"])
    print(data["a"])
    print(data["producttype"])

    if data["mode"] == "192" and float(data["a"]) > time.time() - 10 and float(data["a"]) < time.time() + 10 and data[
        "producttype"] == "0":
        if data["username"] == "admin":
            print("Valid keepalive")
            return "keepalived"
        else:
            print("Invalid keepalive")
            return "No Access", 401

    return "Bad Request", 400

app.run(host="0.0.0.0", port=8090, debug=True)
