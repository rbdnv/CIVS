import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from typing import Tuple, Optional
import json


class CryptoService:
    """Криптографический сервис для работы с контекстом"""
    
    def __init__(self):
        self.hash_algorithm = "SHA256"
    
    def generate_key_pair(self) -> Tuple[str, str]:
        """
        Генерирует пару ключей Ed25519
        Returns: (private_key_pem, public_key_pem)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    
    def compute_hash(self, data: str) -> str:
        """
        Вычисляет SHA-256 хеш от данных
        Formula: H = SHA256(data)
        """
        hash_obj = hashlib.sha256(data.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def compute_hash_chain(self, content: str, previous_hash: Optional[str] = None, timestamp: Optional[str] = None) -> str:
        """
        Вычисляет хеш-цепочку
        Formula: H_n = Hash(Content_n + H_{n-1} + Timestamp)
        """
        if timestamp is None:
            timestamp = self.get_timestamp()
        
        if previous_hash:
            data = content + previous_hash + timestamp
        else:
            data = content + timestamp
        
        return self.compute_hash(data)
    
    def sign_context(self, private_key_pem: str, context_data: dict) -> str:
        """
        Подписывает контекст
        Formulas: 
        - C_norm = Normalize(uid, rid, ts, p)
        - H = SHA256(C_norm)
        - S = Sign_priv(H)
        """
        # Нормализация контекста
        normalized = self._normalize_context(context_data)
        
        # Вычисление хеша
        hash_value = self.compute_hash(normalized)
        
        # Загрузка приватного ключа
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Подпись
        signature = private_key.sign(hash_value.encode('utf-8'))
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, public_key_pem: str, signature_b64: str, context_data: dict) -> bool:
        """
        Верифицирует подпись контекста
        Formulas:
        - C'_norm = Normalize(uid, rid, ts, p)
        - H' = SHA256(C'_norm)
        - Verify_pub(S, H')
        """
        try:
            # Нормализация
            normalized = self._normalize_context(context_data)
            hash_value = self.compute_hash(normalized)
            
            # Загрузка публичного ключа
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Декодирование подписи
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            
            # Верификация
            public_key.verify(signature, hash_value.encode('utf-8'))
            
            return True
        except Exception:
            return False
    
    def compute_hmac(self, data: str, key: str) -> str:
        """Вычисляет HMAC-SHA256"""
        hmac = HMAC(
            key.encode('utf-8'),
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        hmac.update(data.encode('utf-8'))
        return hmac.hexdigest()
    
    def verify_hmac(self, data: str, key: str, expected_hmac: str) -> bool:
        """Проверяет HMAC"""
        computed = self.compute_hmac(data, key)
        return computed == expected_hmac
    
    def _normalize_context(self, context_data: dict) -> str:
        """
        Нормализует контекст для подписи
        Formula: C_norm = Normalize(uid, rid, ts, p)
        """
        # Извлекаем ключевые поля
        parts = []
        
        if 'id' in context_data:
            parts.append(str(context_data['id']))
        if 'user_id' in context_data:
            parts.append(str(context_data['user_id']))
        if 'created_at' in context_data:
            parts.append(str(context_data['created_at']))
        if 'content' in context_data:
            parts.append(str(context_data['content']))
        
        return '|'.join(parts)
    
    def get_timestamp(self) -> str:
        """Получает текущую метку времени"""
        return datetime.utcnow().isoformat()


crypto_service = CryptoService()