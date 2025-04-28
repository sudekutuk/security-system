from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib
import pickle
import time
import os
import pandas as pd

app = Flask(__name__)
app.secret_key = 'gizli_anahtar'

failed_attempts = {}
BANNED_USERS_FILE = 'banned_users.pkl'
LOGIN_ATTEMPTS_FILE = 'login_attempts.csv'

# Banned kullanıcıları dosyadan yükle
def load_banned_users():
    if os.path.exists(BANNED_USERS_FILE):
        with open(BANNED_USERS_FILE, 'rb') as f:
            return pickle.load(f)
    return set()

# Banned kullanıcıları dosyaya kaydet
def save_banned_users():
    with open(BANNED_USERS_FILE, 'wb') as f:
        pickle.dump(banned_users, f)

# Login giriş loglarını CSV'ye kaydet
def log_login_attempt(ip, username, success):
    if not os.path.exists(LOGIN_ATTEMPTS_FILE):
        df = pd.DataFrame(columns=["timestamp", "ip", "username", "success"])
        df.to_csv(LOGIN_ATTEMPTS_FILE, index=False)

    df = pd.read_csv(LOGIN_ATTEMPTS_FILE)
    new_entry = pd.DataFrame([{
        "timestamp": time.time(),
        "ip": ip,
        "username": username,
        "success": int(success)
    }])
    df = pd.concat([df, new_entry], ignore_index=True)
    df.to_csv(LOGIN_ATTEMPTS_FILE, index=False)

# Kullanıcı adı ve şifre kontrol fonksiyonu
def check_login(username, password):
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password, is_admin FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_password, is_admin = result
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if stored_password == hashed_password:
            return True, bool(is_admin)
    return False, False

banned_users = load_banned_users()

@app.route('/', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr

    if request.method == 'GET':
        # Eğer kullanıcı banlanmışsa engelle
        if session.get('username') in banned_users:
            return "Bu kullanıcı banlanmış.", 403
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form['password']

        # Eğer kullanıcı banlandıysa engelle
        if username in banned_users:
            return "Bu kullanıcı banlanmış.", 403

        success, is_admin = check_login(username, password)
        now = time.time()

        # Giriş denemesini kaydet
        log_login_attempt(ip, username, success)

        if success:
            failed_attempts.pop(username, None)
            session['username'] = username
            session['is_admin'] = is_admin
            if is_admin:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('user_panel'))

        else:
            if username not in failed_attempts:
                failed_attempts[username] = [1, now]
            else:
                failed_attempts[username][0] += 1

            # Eğer kullanıcı 5'ten fazla başarısız giriş yaptıysa, 30 saniye içinde
            if failed_attempts[username][0] >= 3 and (now - failed_attempts[username][1]) <= 30:
                banned_users.add(username)
                save_banned_users()
                return "Çok fazla başarısız giriş denemesi. Kullanıcı banlandı.", 403

            return "Giriş başarısız! Kullanıcı adı veya şifre yanlış."

# Admin paneli
@app.route('/admin')
def admin_panel():
    if not session.get('username') or not session.get('is_admin'):
        return redirect(url_for('login', admin='true'))

    return render_template('admin.html', banned_users=banned_users)

# Kullanıcı paneli
@app.route('/user')
def user_panel():
    if not session.get('username'):
        return redirect(url_for('login'))  # Kullanıcı giriş yapmamışsa login sayfasına yönlendir

    # Kullanıcı adı ve rolü almak
    username = session['username']
    is_admin = session['is_admin']

    # Admin'e son giriş bilgisini göster, kullanıcıya ise sadece hoş geldiniz mesajı
    if is_admin:
        last_login_time = session.get('last_login', 'Bilinmiyor')  # Admin için son giriş zamanı
        return render_template('user.html', username=username, is_admin=is_admin, last_login_time=last_login_time)
    else:
        # Kullanıcı için sadece hoş geldiniz mesajı
        return render_template('user.html', username=username, is_admin=is_admin)


# Kullanıcıyı unbanlama
@app.route('/unban', methods=['POST'])
def unban_user():
    if not session.get('username') or not session.get('is_admin'):
        return redirect(url_for('login', admin='true'))

    username_to_unban = request.form['username']
    if username_to_unban in banned_users:
        banned_users.remove(username_to_unban)
        save_banned_users()
    return redirect(url_for('admin_panel'))

# Çıkış
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
