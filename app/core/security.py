from datetime import datetime
from typing import Optional
from app.config import get_settings
from app.core.crypto import crypto_service
from app.core.time_utils import utc_now

settings = get_settings()


class SecurityService:
    """Сервис защиты от атак"""
    
    def detect_tampering(
        self,
        current_content: str,
        stored_hash: str,
        previous_hash: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> bool:
        """
        Обнаружение атаки Context Tampering
        
        Атакующий пытается изменить сохранённый контекст
        Formula: H_n = Hash(Content_n + H_{n-1} + Timestamp)
        """
        computed_hash = crypto_service.compute_hash_chain(
            current_content,
            previous_hash,
            timestamp
        )
        
        return computed_hash != stored_hash
    
    def detect_replay_attack(self, timestamp: str) -> bool:
        """
        Обнаружение атаки Replay Attack
        
        Злоумышленник повторно использует старый контекст
        Formula: T_current - T_request > T_window
        """
        try:
            request_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            current_time = utc_now()
            
            time_diff = (current_time - request_time.replace(tzinfo=None)).total_seconds()
            
            # Если время больше окна - атака
            return time_diff > settings.REPLAY_WINDOW_SECONDS
        except Exception:
            return True  # Если не можем распарсить - считаем атакой
    
    def validate_context_freshness(self, created_at: str, max_age_seconds: int = 3600) -> bool:
        """Проверка свежести контекста"""
        try:
            created_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            current_time = utc_now()
            
            age = (current_time - created_time.replace(tzinfo=None)).total_seconds()
            
            return age < max_age_seconds
        except Exception:
            return False
    
    def check_suspicious_content(self, content: str) -> dict:
        """
        Проверка контента на подозрительные паттерны
        (для Memory Injection атак)
        """
        suspicious_patterns = {
            'script_injection': {
                'script_injection': ['<script>', 'javascript:', 'onerror=', 'onload='],
            },
            'prompt_injection': {
                'ignore previous': [
                    'ignore previous',
                    'ignore all previous',
                    'ignore all previous instructions',
                    'ignore prior instructions',
                    'игнорируй предыдущие инструкции',
                    'игнорируй все предыдущие инструкции',
                    'игнорируй предыдущие правила',
                    'проигнорируй предыдущие инструкции',
                    'не учитывай предыдущие инструкции',
                ],
                'disregard': [
                    'disregard',
                    'disregard previous',
                    'не учитывай',
                    'проигнорируй',
                ],
                'forget rules': [
                    'forget rules',
                    'forget previous rules',
                    'забудь правила',
                    'забудь предыдущие правила',
                    'игнорируй правила',
                ],
                'new instruction': [
                    'new instruction',
                    'new instructions',
                    'follow this instruction instead',
                    'новая инструкция',
                    'новые инструкции',
                    'следуй этой инструкции',
                ],
            },
            'memory_poisoning': {
                'system prompt': [
                    'system prompt',
                    'system instruction',
                    'системный промпт',
                    'системная инструкция',
                ],
                'override': [
                    'override',
                    'overrides previous',
                    'override all previous',
                    'это правило важнее',
                    'важнее всех предыдущих инструкций',
                    'переопредели',
                    'переопределяет предыдущие инструкции',
                ],
                'change your behavior': [
                    'change your behavior',
                    'answer exactly',
                    'answer only',
                    'highest priority rule',
                    'for all future turns',
                    'на все будущие вопросы',
                    'отвечай ровно',
                    'отвечай только',
                    'измени свое поведение',
                    'это правило памяти',
                ],
            },
            'command_injection': {
                'command_injection': ['|', ';', '&&', '$(', '`'],
            },
        }
        
        detected = {}
        content_lower = content.lower()
        
        for category, patterns in suspicious_patterns.items():
            matches = [
                canonical_pattern
                for canonical_pattern, aliases in patterns.items()
                if any(alias in content_lower for alias in aliases)
            ]
            if matches:
                detected[category] = matches
        
        return detected


security_service = SecurityService()
