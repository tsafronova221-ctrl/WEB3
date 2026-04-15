import os
import secrets

# Генерируем случайный SECRET_KEY при каждом запуске приложения
# В продакшене это значение должно храниться в переменной окружения
SECRET_KEY_ENV = os.environ.get('SECRET_KEY')
if SECRET_KEY_ENV:
    SECRET_KEY = SECRET_KEY_ENV
else:
    # Генерируем криптографически стойкий ключ при импорте
    SECRET_KEY = secrets.token_hex(32)


class Config:
    SECRET_KEY = SECRET_KEY
    SQLALCHEMY_DATABASE_URI = "sqlite:///../instance/app.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = False  # Отключено для HTTP (локальная разработка)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
