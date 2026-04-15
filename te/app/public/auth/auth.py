from flask import render_template, request, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, UserMixin
import hashlib
import os
import time
from collections import defaultdict

from .__blueprint__ import auth_bp
from app import login_manager


# Хранилище пользователей с хешированными паролями
# В продакшене используйте базу данных и bcrypt/argon2
def hash_password(p):
    """Хеширование пароля с солью"""
    salt = os.environ.get('PASSWORD_SALT', 'default_salt_change_in_production')
    return hashlib.sha256((salt + p).encode()).hexdigest()


# Пароли хранятся в хешированном виде
# admin: admin123 (измените в production!)
# teacher: teacher123 (измените в production!)
USERS = {
    "admin": hash_password("admin123"),
    "teacher": hash_password("teacher123"),
}

# Защита от перебора паролей (brute-force)
# Хранит время последней неудачной попытки и количество попыток для каждого IP
login_attempts = defaultdict(lambda: {"count": 0, "last_attempt": 0})
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 минут блокировки


def check_login_lockout(ip_address):
    """Проверка, заблокирован ли IP для входа"""
    if ip_address not in login_attempts:
        return False
    
    attempt_info = login_attempts[ip_address]
    current_time = time.time()
    
    # Если прошло достаточно времени после последней попытки - сбрасываем счетчик
    if current_time - attempt_info["last_attempt"] > LOCKOUT_TIME:
        login_attempts[ip_address] = {"count": 0, "last_attempt": 0}
        return False
    
    # Если превышено количество попыток - блокируем
    if attempt_info["count"] >= MAX_LOGIN_ATTEMPTS:
        return True
    
    return False


def record_failed_login(ip_address):
    """Запись неудачной попытки входа"""
    current_time = time.time()
    attempt_info = login_attempts[ip_address]
    
    # Если прошло достаточно времени - сбрасываем счетчик
    if current_time - attempt_info["last_attempt"] > LOCKOUT_TIME:
        login_attempts[ip_address] = {"count": 1, "last_attempt": current_time}
    else:
        attempt_info["count"] += 1
        attempt_info["last_attempt"] = current_time


def record_successful_login(ip_address):
    """Сброс счетчика после успешного входа"""
    if ip_address in login_attempts:
        login_attempts[ip_address] = {"count": 0, "last_attempt": 0}


class SimpleUser(UserMixin):
    def __init__(self, username):
        self.id = username


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip_address = request.remote_addr
        
        # Проверка на блокировку IP
        if check_login_lockout(ip_address):
            remaining_time = int(LOCKOUT_TIME - (time.time() - login_attempts[ip_address]["last_attempt"]))
            return render_template(
                "admin/login.html", 
                error=f"Слишком много неудачных попыток входа. Попробуйте через {remaining_time} сек."
            )
        
        username = request.form.get("username")
        password = request.form.get("password")

        if username in USERS and USERS[username] == hash_password(password):
            record_successful_login(ip_address)
            user = SimpleUser(username)
            login_user(user)
            return redirect(url_for("admin.index"))

        record_failed_login(ip_address)
        return render_template("admin/login.html", error="Неверный логин или пароль")

    return render_template("admin/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
