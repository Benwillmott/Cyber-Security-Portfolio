from flask import Flask, request, render_template_string, redirect, url_for, flash, session
import bcrypt
import hashlib

app = Flask(__name__)
app.secret_key = "change_this_in_real_app"

# -----------------------------
# In-memory "databases"
# -----------------------------
# Insecure: plain-text passwords
insecure_users = {}          # {username: password}
insecure_transactions = []   # list of strings

# Secure: hashed passwords + integrity hashes
secure_users = {}            # {username: password_hash}
secure_transactions = [ {"data": "User A sends £5000", "hash": "abc123"} ]    # list of dicts: {"data": str, "hash": str}


# -----------------------------
# Simple HTML templates
# -----------------------------
home_template = """
<h1>Secure Banking Demo</h1>
<p><a href="{{ url_for('insecure_register') }}">Insecure Register</a> |
<a href="{{ url_for('insecure_login') }}">Insecure Login</a> |
<a href="{{ url_for('secure_register') }}">Secure Register</a> |
<a href="{{ url_for('secure_login') }}">Secure Login</a></p>
"""

insecure_register_template = """
<h2>Insecure Register (Plain-text Passwords)</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Register</button>
</form>
<p><a href="{{ url_for('home') }}">Back</a></p>
"""

insecure_login_template = """
<h2>Insecure Login</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
<p><a href="{{ url_for('home') }}">Back</a></p>
"""

insecure_dashboard_template = """
<h2>Insecure Dashboard</h2>
<p>Logged in as: {{ user }}</p>
<h3>Submit Transaction (No Integrity Check)</h3>
<form method="post" action="{{ url_for('insecure_submit_transaction') }}">
  Transaction text: <input name="tx"><br>
  <button type="submit">Submit</button>
</form>

<h3>All Transactions (Can Be Tampered)</h3>
<ul>
{% for t in transactions %}
  <li>{{ t }}</li>
{% endfor %}
</ul>

<p><a href="{{ url_for('home') }}">Back</a></p>
"""

secure_register_template = """
<h2>Secure Register (Hashed Passwords)</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Register</button>
</form>
<p><a href="{{ url_for('home') }}">Back</a></p>
"""

secure_login_template = """
<h2>Secure Login</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
<p><a href="{{ url_for('home') }}">Back</a></p>
"""

secure_dashboard_template = """
<h2>Secure Dashboard</h2>
<p>Logged in as: {{ user }}</p>

<h3>Submit Transaction (With Integrity Hash)</h3>
<form method="post" action="{{ url_for('secure_submit_transaction') }}">
  Transaction text: <input name="tx"><br>
  <button type="submit">Submit</button>
</form>

<h3>All Transactions (Integrity Verified)</h3>
<ul>
{% for t in transactions %}
  <li>
    {{ t["data"] }} -
    {% if t["valid"] %}
      <strong>INTEGRITY OK</strong>
    {% else %}
      <strong style="color:red;">TAMPERED!</strong>
    {% endif %}
  </li>
{% endfor %}
</ul>

<p><a href="{{ url_for('home') }}">Back</a></p>
"""


# -----------------------------
# Home
# -----------------------------
@app.route("/")
def home():
    return render_template_string(home_template)


# =============================
# INSECURE IMPLEMENTATION
# =============================

@app.route("/insecure/register", methods=["GET", "POST"])
def insecure_register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]  # stored in plain text
        insecure_users[username] = password
        flash("Insecure user registered (password stored in plain text).")
        return redirect(url_for("insecure_login"))
    return render_template_string(insecure_register_template)


@app.route("/insecure/login", methods=["GET", "POST"])
def insecure_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        stored = insecure_users.get(username)

        if stored is not None and stored == password:
            session["insecure_user"] = username
            return redirect(url_for("insecure_dashboard"))
        else:
            flash("Invalid credentials (insecure).")
    return render_template_string(insecure_login_template)


@app.route("/insecure/dashboard")
def insecure_dashboard():
    user = session.get("insecure_user")
    if not user:
        return redirect(url_for("insecure_login"))
    return render_template_string(
        insecure_dashboard_template,
        user=user,
        transactions=insecure_transactions
    )


@app.route("/insecure/submit", methods=["POST"])
def insecure_submit_transaction():
    user = session.get("insecure_user")
    if not user:
        return redirect(url_for("insecure_login"))

    tx = request.form["tx"]
    # No integrity protection: just store raw text
    insecure_transactions.append(tx)
    flash("Transaction submitted (no integrity check).")
    return redirect(url_for("insecure_dashboard"))


# =============================
# SECURE IMPLEMENTATION
# =============================

@app.route("/secure/register", methods=["GET", "POST"])
def secure_register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        # Hash password with bcrypt
        salt = bcrypt.gensalt()
        pw_hash = bcrypt.hashpw(password, salt)

        secure_users[username] = pw_hash
        flash("Secure user registered (password hashed with bcrypt).")
        return redirect(url_for("secure_login"))
    return render_template_string(secure_register_template)


@app.route("/secure/login", methods=["GET", "POST"])
def secure_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()
        stored_hash = secure_users.get(username)

        if stored_hash and bcrypt.checkpw(password, stored_hash):
            session["secure_user"] = username
            return redirect(url_for("secure_dashboard"))
        else:
            flash("Invalid credentials (secure).")
    return render_template_string(secure_login_template)


@app.route("/secure/dashboard")
def secure_dashboard():
    user = session.get("secure_user")
    if not user:
        return redirect(url_for("secure_login"))

    # Verify integrity of each stored transaction
    verified_transactions = []
    for entry in secure_transactions:
        data = entry["data"]
        stored_hash = entry["hash"]
        current_hash = hashlib.sha256(data.encode()).hexdigest()
        valid = (current_hash == stored_hash)
        verified_transactions.append({
            "data": data,
            "valid": valid
        })

    return render_template_string(
        secure_dashboard_template,
        user=user,
        transactions=verified_transactions
    )


@app.route("/secure/submit", methods=["POST"])
def secure_submit_transaction():
    user = session.get("secure_user")
    if not user:
        return redirect(url_for("secure_login"))

    tx = request.form["tx"]
    # Generate integrity hash of transaction data
    tx_hash = hashlib.sha256(tx.encode()).hexdigest()

    secure_transactions.append({
        "data": tx,
        "hash": tx_hash
    })

    flash("Transaction submitted with integrity hash.")
    return redirect(url_for("secure_dashboard"))
    
@app.route("/tamper")
def tamper():
    if secure_transactions:
        secure_transactions[0]["data"] = "User A sends £9999"
    return "Tampered!"
    
@app.route("/debug-users")
def debug_users():
    return str({
        "insecure_users": insecure_users,
        "secure_users": secure_users
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
