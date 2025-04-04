from flask import Flask, request, render_template_string, redirect
import sqlite3, bcrypt, random

app = Flask(__name__)
app.secret_key = 'supersecret'

# --- HTML Template ---
html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>HashAlgo</title>
    <style>
        body {
            margin: 0;
            font-family: 'Trebuchet MS', sans-serif;
            background-color: #ffe4e1;
        }
        .header {
            text-align: center;
            font-size: 36px;
            font-weight: bold;
            padding: 20px;
            font-family: 'Courier New', Courier, monospace;
        }
        .dev-link {
            position: absolute;
            top: 10px;
            right: 10px;
        }
        .dev-link a {
            text-decoration: none;
            background-color: #888;
            color: white;
            padding: 8px 16px;
            border-radius: 6px;
        }
        .container {
            display: flex;
            justify-content: flex-end;
            padding: 60px;
        }
        .login-box {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 2px 2px 10px rgba(0,0,0,0.2);
            width: 300px;
        }
        .login-box input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
        }
        .login-box button {
            width: 100%;
            padding: 10px;
            background: linear-gradient(to right, pink, grey);
            color: white;
            border: none;
            font-weight: bold;
            border-radius: 6px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            font-size: 14px;
            color: #555;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
    </style>
    <script>
        function togglePassword() {
            var pwd = document.getElementById("password");
            pwd.type = pwd.type === "password" ? "text" : "password";
        }
    </script>
</head>
<body>
    <div class="header">HashAlgo</div>
    <div class="dev-link"><a href="/dev">Developer</a></div>
    <div class="container">
        <div class="login-box">
            <form method="POST">
                <input type="text" name="username" placeholder="Enter Gmail" required>
                <input type="password" name="password" placeholder="Password" id="password" required>
                <input type="checkbox" onclick="togglePassword()"> Show Password
                <button type="submit">Login</button>
            </form>
            <p style="color:red;">{{ message }}</p>
        </div>
    </div>
    <div class="footer">
        &copy; 2025 HashAlgo Inc. All rights reserved.
    </div>
</body>
</html>
"""

# Developer login
dev_auth_template = """
<form method="POST" style="text-align:center;padding-top:100px;">
    <h2>Developer Access</h2>
    <input type="password" name="devpass" placeholder="Enter password" required>
    <br><br>
    <button type="submit">Access</button>
</form>
"""

# Updated Developer Panel (using loop.index for serial numbers)
dev_panel_template = """
<h2 style="text-align:center;">User Data</h2>
<table border=1 cellspacing=0 cellpadding=10 align="center">
<tr><th>Serial</th><th>Email</th><th>Hashed Password</th><th>Action</th></tr>
{% for u in users %}
<tr>
    <td>{{ loop.index }}</td>
    <td>{{ u[1] }}</td>
    <td>{{ u[2] }}</td>
    <td>
        <form method="POST" action="/delete" style="margin:0;">
            <input type="hidden" name="id" value="{{ u[0] }}">
            <button type="submit">Delete</button>
        </form>
    </td>
</tr>
{% endfor %}
</table>
<br><center><a href="/">Back to Login</a></center>
"""

# DB init
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    conn.commit()
    conn.close()

# Login/Register
@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username.endswith("@gmail.com"):
            msg = "Only Gmail addresses allowed."
        else:
            conn = sqlite3.connect("users.db")
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0] >= 100:
                msg = "User limit (100) reached."
            else:
                cur.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cur.fetchone()
                if user:
                    if bcrypt.checkpw(password.encode(), user[2].encode()):
                        return f"<h2>Welcome back {username}!</h2><br><a href='/'>Logout</a>"
                    else:
                        msg = "Incorrect password."
                else:
                    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
                    conn.commit()
                    return f"<h2>Registered Successfully! Welcome {username}!</h2><br><a href='/'>Logout</a>"
            conn.close()
    return render_template_string(html_template, message=msg)

# Developer panel access
@app.route('/dev', methods=['GET', 'POST'])
def dev():
    if request.method == 'POST':
        if request.form['devpass'] == '12345':
            conn = sqlite3.connect("users.db")
            cur = conn.cursor()
            cur.execute("SELECT * FROM users ORDER BY id ASC")
            users = cur.fetchall()
            conn.close()
            return render_template_string(dev_panel_template, users=users)
        else:
            return "<h3 style='text-align:center;color:red;'>Wrong password. <a href='/'>Back</a></h3>"
    return render_template_string(dev_auth_template)

# Delete user
@app.route('/delete', methods=['POST'])
def delete_user():
    uid = request.form['id']
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return redirect('/dev')

# Start App
if __name__ == '__main__':
    init_db()
    port = random.randint(3000, 9999)
    print(f"Running on http://127.0.0.1:{port}")
    app.run(debug=True, port=port)
