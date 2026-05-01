from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "Demo App Running"

@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    return str(eval(cmd))  # intentionally vulnerable

if __name__ == "__main__":
    app.run()