from typing import Dict, List, Optional, Tuple
from datetime import datetime
from app.config import get_settings
from app.core.crypto import crypto_service

settings = get_settings()


class TrustScoreCalculator:
    """
    Калькулятор Trust Score для верификации контекста
    
    Formula: TrustScore = Σ w_i * f_i
    """
    
    # Веса признаков (можно настраивать)
    DEFAULT_WEIGHTS = {
        'signature_valid': 0.3,
        'hash_chain_valid': 0.2,
        'timestamp_fresh': 0.15,
        'no_tampering': 0.25,
        'source_trusted': 0.1,
    }
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or self.DEFAULT_WEIGHTS
    
    def calculate(self, context_data: Dict, verification_result: Dict) -> float:
        """
        Вычисляет Trust Score
        Returns: float between 0 and 1
        """
        score = 0.0
        
        # 1. Проверка подписи (вес 0.3)
        if verification_result.get('signature_valid', False):
            score += self.weights['signature_valid']
        
        # 2. Проверка хеш-цепочки (вес 0.2)
        if verification_result.get('hash_chain_valid', False):
            score += self.weights['hash_chain_valid']
        
        # 3. Свежесть временной метки (вес 0.15)
        if verification_result.get('timestamp_fresh', False):
            score += self.weights['timestamp_fresh']
        
        # 4. Отсутствие tampering (вес 0.25)
        if not verification_result.get('tampering_detected', True):
            score += self.weights['no_tampering']
        
        # 5. Доверие к источнику (вес 0.1)
        if verification_result.get('source_trusted', False):
            score += self.weights['source_trusted']
        
        return round(score, 3)
    
    def classify(self, trust_score: float) -> str:
        """
        Классифицирует результат на основе Trust Score
        
        Returns: ACCEPT | QUARANTINE | REJECT
        """
        if trust_score >= settings.TRUST_THRESHOLD_ACCEPT:
            return "ACCEPT"
        elif trust_score >= settings.TRUST_THRESHOLD_QUARANTINE:
            return "QUARANTINE"
        else:
            return "REJECT"


class VerifierService:
    """Сервис верификации контекста"""
    
    def __init__(self):
        self.trust_calculator = TrustScoreCalculator()
    
    async def verify_context(
        self,
        context_record: Dict,
        stored_signature: Optional[str] = None,
        stored_public_key: Optional[str] = None,
    ) -> Tuple[float, str, Dict]:
        """
        Верифицирует контекст и вычисляет Trust Score
        
        Returns: (trust_score, classification, details)
        """
        verification_details = {
            'signature_valid': False,
            'hash_chain_valid': False,
            'timestamp_fresh': False,
            'tampering_detected': False,
            'replay_attack_detected': False,
            'source_trusted': False,
        }
        
        # 1. Проверка подписи
        if stored_signature and stored_public_key:
            signature_valid = crypto_service.verify_signature(
                stored_public_key,
                stored_signature,
                context_record
            )
            verification_details['signature_valid'] = signature_valid
        
        # 2. Проверка хеш-цепочки
        if context_record.get('content_hash'):
            timestamp = context_record.get('created_at')
            computed_hash = crypto_service.compute_hash_chain(
                context_record['content'],
                context_record.get('previous_hash'),
                timestamp
            )
            verification_details['hash_chain_valid'] = (
                computed_hash == context_record['content_hash']
            )
        
        # 3. Проверка временной метки
        if context_record.get('created_at'):
            created_at = context_record['created_at']
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            
            now = datetime.utcnow()
            time_diff = (now - created_at.replace(tzinfo=None)).total_seconds()
            verification_details['timestamp_fresh'] = time_diff < 3600  # 1 час
        
        # 4. Проверка на tampering
        # (подробная проверка в security.py)
        
        # 5. Проверка источника
        if context_record.get('data_source_id'):
            verification_details['source_trusted'] = True
        
        # Вычисление Trust Score
        trust_score = self.trust_calculator.calculate(
            context_record,
            verification_details
        )
        
        # Классификация
        classification = self.trust_calculator.classify(trust_score)
        
        return trust_score, classification, verification_details
    
    def analyze_features(self, content: str) -> Dict[str, float]:
        """
        Анализирует контент и извлекает признаки для Trust Score
        """
        features = {}
        
        # Пример: длина контента
        features['content_length'] = min(len(content) / 10000, 1.0)
        
        # Пример: наличие подозрительных паттернов
        suspicious_patterns = ['<script>', 'javascript:', 'onerror=', '{{']
        features['suspicious_patterns'] = 1.0 if any(p in content.lower() for p in suspicious_patterns) else 0.0
        
        return features


verifier_service = VerifierService()