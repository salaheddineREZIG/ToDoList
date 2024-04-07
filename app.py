from flask import Flask, render_template, request, redirect, flash, session
from cs50 import SQL
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from Functions import validate
import datetime

app = Flask(__name__)
db = SQL("sqlite:///DataBase.db")

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


priorities = ["Low", "Medium", "High"]
statuses = ["To-Do", "Doing", "Completed"]


@app.route("/")
def Index():
    if session.get("loggedIn"):
        return render_template("Index.html", priorities=priorities, statuses=statuses, tasks=db.execute("SELECT * FROM tasks where user_id = ?", session["userId"]))
    else:
        return render_template("Landing.html")


@app.route("/Add", methods=["POST"])
def Add():
    title = request.form.get("title")
    description = request.form.get("description")
    dueDate = request.form.get("dueDate")
    dueTime = request.form.get("dueTime")
    priority = request.form.get("priority")

    if description is not None and title is not None:
        if len(description) > 100 or len(title) > 100:
            flash("please enter a shorter title anddescription", "error")
            return redirect("/")
    date_format = "%Y-%m-%d %H:%M"
    dueDate = dueDate + " " + dueTime
    dueDate = datetime.datetime.strptime(dueDate, date_format)
    if dueDate < datetime.datetime.now():
        flash("invaild due date", "error")
        return redirect("/")
    if not priority in priorities:
        flash("invalid priority", "error")
        return redirect("/")

    db.execute("INSERT INTO tasks (user_id,title,description,due_date,priority) VALUES (?,?,?,?,?)",
               session["userId"], title, description, dueDate, priority)
    flash("task added succesfully", "message")
    return redirect("/")

@app.route("/Delete")
def Delete():
    id = request.args.get("id")
    db.execute("DELETE FROM tasks WHERE task_id = ?",id)
    flash("Task deleted successfully","success")
    return redirect("/")

@app.route("/ChangeStatus", methods=["POST"])
def ChangeStaus():
    newStatus = request.form.get("status")
    id = request.args.get("id")
    db.execute("UPDATE tasks SET status = ? where task_id = ?",newStatus,id)
    return redirect("/")
@app.route("/SignUp", methods=["GET", "POST"])
def SignUp():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        confirmation = request.form.get("confirmation")

        if db.execute("SELECT * FROM users WHERE username = ?", username):
            flash("Username already exists", "error")
            return redirect("/SignUp")

        if not validate(email):
            flash("Invalid email format", "error")
            return redirect("/SignUp")

        if db.execute("SELECT * FROM users WHERE email =?", email):
            flash("Email already exists", "error")
            return redirect("/SignUp")

        if password != confirmation:
            flash("Passwords don't match", "error")
            return redirect("/SignUp")

        hashedPassword = generate_password_hash(password, method='pbkdf2')

        db.execute("INSERT INTO users (username, email, hash) VALUES (?, ?, ?)",
                   username, email, hashedPassword)

        session["userId"] = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
        session["username"] = username
        session["email"] = email
        session["loggedIn"] = True

        flash("Signed up successfully", "success")
        return redirect("/")
    else:
        return render_template("SignUp.html")


@app.route("/LogIn", methods=["GET", "POST"])
def Login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        info = db.execute("SELECT * FROM users WHERE username = ?", username)
        if not info:
            flash("No username found", "error")
            return redirect("/LogIn")
        if info[0]["username"] == username and check_password_hash(info[0]["hash"], password):
            session["userId"] = info[0]["id"]
            session["username"] = username
            session["loggedIn"] = True

            flash("Logged in successfully", "success")
            return redirect("/")
        else:
            flash("Invalid username and/or password", "error")
            return redirect("/LogIn")
    else:
        return render_template("LogIn.html")


@app.route("/LogOut")
def LogOut():
    session.clear()
    session["loggedIn"] = False
    flash("Logged out succesfully", "success")
    return redirect("/")
