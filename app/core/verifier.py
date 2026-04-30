from typing import Dict, List, Optional, Tuple
from datetime import datetime
from app.config import get_settings
from app.core.crypto import crypto_service
from app.core.time_utils import utc_now

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

    def finalize_verification(self, context_record: Dict, verification_details: Dict) -> Tuple[float, str]:
        """
        Приводит детали проверки к финальному trust score и classification.

        Security findings must influence the final result, even if they were
        detected after the initial crypto/hash checks.
        """
        finalized_details = verification_details.copy()

        # Replay makes the context effectively stale for trust scoring.
        if finalized_details.get('replay_attack_detected', False):
            finalized_details['timestamp_fresh'] = False

        trust_score = self.trust_calculator.calculate(
            context_record,
            finalized_details
        )
        classification = self.trust_calculator.classify(trust_score)

        # Tampering is a hard failure: integrity is broken.
        if finalized_details.get('tampering_detected', False):
            classification = "REJECT"
        # Replay must never be fully accepted.
        elif finalized_details.get('replay_attack_detected', False) and classification == "ACCEPT":
            classification = "QUARANTINE"

        verification_details.update(finalized_details)
        return trust_score, classification
    
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
            
            now = utc_now()
            time_diff = (now - created_at.replace(tzinfo=None)).total_seconds()
            verification_details['timestamp_fresh'] = time_diff < 3600  # 1 час
        
        # 4. Проверка на tampering
        # (подробная проверка в security.py)
        
        # 5. Проверка источника
        if context_record.get('data_source_id'):
            verification_details['source_trusted'] = True
        
        trust_score, classification = self.finalize_verification(
            context_record,
            verification_details,
        )
        
        return trust_score, classification, verification_details

    def verify_file_ingest(
        self,
        *,
        content_hash: str,
        suspicious_content: Optional[Dict[str, List[str]]] = None,
    ) -> Tuple[float, str, Dict]:
        """
        Evaluates an uploaded RAG file as untrusted ingest.

        Files entering RAG are not trusted memory yet. A clean file can be
        quarantined for later review/promotion, while suspicious content is
        rejected immediately.
        """
        suspicious_content = suspicious_content or {}
        is_safe = len(suspicious_content) == 0

        if is_safe:
            trust_score = settings.TRUST_THRESHOLD_QUARANTINE
            classification = "QUARANTINE"
            ingest_status = "QUARANTINED"
            message = (
                "Файл прошёл базовую проверку и помещён в ingest/quarantine. "
                "Он ещё не считается trusted memory."
            )
        else:
            trust_score = 0.0
            classification = "REJECT"
            ingest_status = "REJECTED"
            message = (
                "Файл отклонён на этапе ingest: обнаружены подозрительные паттерны."
            )

        verification_details = {
            "signature_valid": False,
            "hash_chain_valid": False,
            "timestamp_fresh": True,
            "tampering_detected": False,
            "replay_attack_detected": False,
            "source_trusted": False,
            "content_hash": content_hash,
            "suspicious_content": suspicious_content,
            "is_safe": is_safe,
            "ingest_status": ingest_status,
            "eligible_for_trusted_memory": False,
            "requires_review": is_safe,
            "message": message,
        }

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
