from flask import Flask

app = Flask(__name__)


@app.route('/')
def suspicious_page():
    # This is just an example of a suspicious page with fake login form
    return '''
    <html>
        <head>
            <title>Secure Login</title>
        </head>
        <body>
            <h1>Login to Secure Your Account</h1>
            <form action="/submit-login" method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username"><br><br>
                <label for="password">Password:Fake</label>
                <input type="password" id="password" name="password"><br><br>
                <input type="submit" value="Login">
            </form>
        </body>
    </html>
    '''


if __name__ == '__main__':
    app.run(debug=True, port=3000)
