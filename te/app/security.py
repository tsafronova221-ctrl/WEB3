import hashlib
import os
import secrets


def hash_password(p):
    """Хеширование пароля с солью для безопасного хранения"""
    salt = os.environ.get('PASSWORD_SALT', 'default_salt_change_in_production')
    return hashlib.sha256((salt + p).encode()).hexdigest()


def verify_password(plain, hashed):
    """Проверка пароля"""
    return hash_password(plain) == hashed


def generate_watermark_hash(attempt):
    """Генерация хеша водяного знака с использованием случайного ключа"""
    # Используем случайный ключ для каждой сессии приложения
    secret = os.environ.get('WATERMARK_SECRET', secrets.token_hex(16))
    data = f"{secret}|{attempt.id}|{attempt.student_id}|{attempt.lab_id if hasattr(attempt, 'lab_id') else attempt.protection_id}|{attempt.score}|{attempt.finished_at}"
    return hashlib.sha256(data.encode()).hexdigest()[:24]
