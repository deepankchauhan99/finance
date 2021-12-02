import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
# from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy import text

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'
# db = SQLAlchemy(app)
db = SQL('sqlite:///finance.db')

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Fetching the user id and username of the currently logged user
    user_id = session.get("user_id")
    stocks = db.execute("SELECT * FROM stocks WHERE user_id = ?;", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    money = db.execute("SELECT SUM(current_value) AS money FROM stocks WHERE user_id = ?;", user_id)

    # Try and catch when there are no stocks in the user list.
    try:
        total = float(money[0]["money"]) + float(cash[0]["cash"])
    except NameError:
        total = float(cash[0]["cash"])
    except TypeError:
        total = float(cash[0]["cash"])

    # Refresh the prices of all the stocks in the portfolio
    for i in range(len(stocks)):
        stock = lookup(stocks[i]["stock"])
        price = stock["price"]
        current_value = price * stocks[i]["shares"]
        db.execute("UPDATE stocks SET price = ?, current_value = ? WHERE user_id = ? AND stock = ?;",
                   price, current_value, user_id, stock["symbol"])

    return render_template("index.html", stocks=stocks, cash=cash[0]["cash"], total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Fetching variables from the form
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            if float(shares) - int(float(shares)) != 0:
                return apology("Please enter a whole number.", 400)
            if float(shares) < 0:
                return apology("Please enter a positive value.", 400)
        except ValueError:
            return apology("Please enter a numeric value.", 400)

        # To make sure the sure fill the required data
        if not symbol:
            return apology("Please enter a symbol", 400)
        if not shares:
            return apology("Please enter a number of shares", 400)

        try:
            stock = lookup(symbol)
            total_amount = float(stock["price"]) * float(shares)
            user_id = session.get("user_id")
            username = db.execute("SELECT username FROM users WHERE id = ?", user_id)
            balance_dict = db.execute("SELECT cash FROM users where id = ?", user_id)
            balance = float(balance_dict[0]["cash"])

            # To make sure the user has enough balance in their account
            if total_amount > balance:
                return apology("Sorry! Low Balance!", 400)

            # Updating the database to add the bought shares in user's account
            else:
                db.execute("INSERT INTO transactions (username, type, stock, stock_name, price, shares, total, time) VALUES (?,?,?,?,?,?,?,datetime());",
                           username[0]["username"], "BUY", stock["symbol"], stock["name"], stock["price"], shares, total_amount)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance - total_amount, user_id)
                checker = db.execute("SELECT stock FROM stocks WHERE user_id = ?", user_id)

                # Flag to check if the stock already bought by the user
                flag = False
                for i in range(len(checker)):
                    if stock["symbol"] == checker[i]["stock"]:
                        old_shares = db.execute("SELECT shares FROM stocks WHERE stock = ? AND user_id = ?",
                                                stock["symbol"], user_id)
                        new_value = int(old_shares[0]["shares"]) + int(shares)
                        db.execute("UPDATE stocks SET shares = ?, current_value = ? WHERE stock = ? AND user_id = ?",
                                   new_value, new_value * float(stock["price"]), stock["symbol"], user_id)
                        flag = True

                # Inserting new entry into the table
                if flag == False:
                    db.execute("INSERT INTO stocks (user_id, stock, stock_name, price, shares, current_value) VALUES (?,?,?,?,?,?);",
                               user_id, stock["symbol"], stock["name"], stock["price"], shares, total_amount)

                # Custom success message after purchasing shares
                success_message = shares + " shares of " + stock["name"] + " (" + stock["symbol"] + ") successfully bought at " + usd(total_amount) + "."
                flash(success_message)

        # Checks if a valid stock symbol is entered for purchasing
        except Exception:
            return apology("Not a valid symbol!", 400)

        # Redirecting to the homepage
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Fetching the user id and username of the currently logged user
    user_id = session.get("user_id")
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)

    # Getting all the transactions and the remaining case of the current logged in user from the database
    transactions = db.execute("SELECT * FROM transactions WHERE username = ?;", username[0]["username"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

    return render_template("history.html", transactions=transactions, cash=cash[0]["cash"])


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # If request is GET
    if request.method == "GET":
        return render_template("quote.html")

    # For POST request
    else:
        symbol = request.form.get("symbol")
        try:
            # Looking up for the stock via API call
            stock = lookup(symbol)

            # Flashing a custom message showing the price of the stock
            message = "A share of " + stock["name"] + " (" + stock["symbol"] + ") costs " + usd(stock["price"]) + "."
            flash(message)

            return render_template("quote.html")
        # If the stock symbol is not found
        except Exception:
            return apology("Not a valid symbol!", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Variables taken from the form
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    # User reached route via GET
    if request.method == "GET":
        return render_template("register.html")

    # User reached route via POST (as by submitting a form via POST)
    else:

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password was submitted
        if not request.form.get("confirmation"):
            return apology("must repeat password", 400)

        # Check if the repeated password matches
        if password != confirmation:
            return apology("password didn't match", 400)

        # Password Validation

        allowedSymbols = ['$', '@', '#', '%', '!', '&', '*', '-', '_', '+', '?']

        if not any(char.isdigit() for char in password):
            return apology("password should have atleast one numeral.", 400)

        if not any(char.isupper() for char in password):
            return apology("password should contain atleast one uppercase letter.", 400)

        if not any(char.islower() for char in password):
            return apology("password should contain atleast one lowercase letter.", 400)

        if not any(char in allowedSymbols for char in password):
            return apology("password should contain atleast one special character ($,@,#,%).", 400)

        if len(password) < 8:
            return apology("password should contain minimum 8 characters", 400)

        # Hashing the password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Adding user to the database
        try:
            db_insertion = db.execute("INSERT INTO users (username, hash) VALUES (?,?);", username, password_hash)

        # If the user already exists
        except Exception:
            return apology("username already exist!", 400)

        # Success message
        flash("User Registered")

        # Prompted user to login after registering
        return render_template("login.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session.get("user_id")
    stocks = db.execute("SELECT * FROM stocks WHERE user_id = ?", user_id)

    if request.method == "GET":
        return render_template("sell.html", stocks=stocks)

    else:
        selected_stock = request.form.get("symbol")
        available_shares = db.execute("SELECT * FROM stocks WHERE user_id = ? AND stock = ?", user_id, selected_stock)
        selected_shares = request.form.get("shares")

        # If users exceeds the available number of shares to sell
        if int(selected_shares) > int(available_shares[0]["shares"]):
            return apology("Not enough shares available of this stock!", 400)

        else:
            remaining_shares = int(available_shares[0]["shares"]) - int(selected_shares)
            remainder = lookup(selected_stock)
            remainder_cash = float(remainder["price"]) * int(selected_shares)
            username = db.execute("SELECT username FROM users WHERE id = ?", user_id)

            # If all the shares of a stock are sold
            if remaining_shares == 0:
                db.execute("UPDATE users SET cash = cash + ?;", remainder_cash)
                db.execute("INSERT INTO transactions (username, type, stock, stock_name, price, shares, total, time) VALUES (?,?,?,?,?,?,?,datetime());",
                           username[0]["username"], "SELL", remainder["symbol"], remainder["name"], remainder["price"], selected_shares, remainder_cash)
                db.execute("DELETE FROM stocks WHERE user_id = ? AND stock = ?;", user_id, selected_stock)

            # If a part of the shares are sold
            else:
                stock_residual = float(remainder["price"]) * int(remaining_shares)

                db.execute("UPDATE users SET cash = cash + ?;", remainder_cash)
                db.execute("INSERT INTO transactions (username, type, stock, stock_name, price, shares, total, time) VALUES (?,?,?,?,?,?,?,datetime());",
                           username[0]["username"], "SELL", remainder["symbol"], remainder["name"], remainder["price"], selected_shares, remainder_cash)
                db.execute("UPDATE stocks SET shares = ?, current_value = ? WHERE user_id = ? AND stock = ?;",
                           remaining_shares, stock_residual, user_id, selected_stock)

            # Sell success message
            sell_message = selected_shares + ' shares of ' + remainder["name"] + ' (' + remainder["symbol"] + ') sold at ' + usd(remainder["price"]) + '.'
            flash(sell_message)

        # Redirecting to index page
        return redirect("/")


@app.route("/addmoney", methods=["GET", "POST"])
@login_required
def addmoney():

    # To get the addmoney page
    if request.method == "GET":
        return render_template("addmoney.html")

    else:
        addmoney = request.form.get("addmoney")
        user_id = session.get("user_id")

        # Add money to the user's account
        db.execute("UPDATE users SET cash = cash + ? where id = ?", addmoney, user_id)
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
