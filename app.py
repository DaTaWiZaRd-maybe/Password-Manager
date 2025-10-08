from flask import Flask, render_template, request, redirect, url_for, flash
from database import add_password, list_passwords, search_password
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        add_password(website, username, password)
        flash('Password added successfully!', 'success')
        return redirect(url_for('add'))
    return render_template('add.html')

@app.route('/view')
def view():
    passwords = list_passwords()
    return render_template('view.html', passwords=passwords)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        term = request.form['term']
        results = search_password(term)
        return render_template('search.html', results=results, term=term)
    return render_template('search.html', results=None)

if __name__ == '__main__':
    app.run(debug=True)

