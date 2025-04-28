import sqlite3
import hashlib

def add_user(username, password, is_admin=False):
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', 
                       (username, hashed_password, int(is_admin)))
        conn.commit()
        print(f"Kullanıcı '{username}' başarıyla eklendi.")
    except sqlite3.IntegrityError:
        print(f"Kullanıcı adı '{username}' zaten mevcut.")
    conn.close()

# Buraya kullanıcı bilgilerini giriyorsun
add_user('admin', 'admin123', True)  # Admin kullanıcı
add_user('kullanici1', 'sifre123', False)  # Normal kullanıcı
add_user('sude','9999',False)