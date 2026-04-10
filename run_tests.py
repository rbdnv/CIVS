#!/usr/bin/env python3
"""Запуск всех тестов"""
import sys
sys.path.insert(0, 'D:/Programming/Diplom/civs')

from app.core.crypto import crypto_service
from app.core.security import security_service
from app.core.verifier import TrustScoreCalculator

def test_all():
    print("=" * 60)
    print("ЗАПУСК ТЕСТОВ")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    # Тест 1: Генерация ключей
    try:
        pk, pubk = crypto_service.generate_key_pair()
        assert "BEGIN PRIVATE KEY" in pk
        print("[PASS] test_generate_key_pair")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_generate_key_pair: {e}")
        failed += 1
    
    # Тест 2: Хеширование
    try:
        h = crypto_service.compute_hash("test")
        assert len(h) == 64
        print("[PASS] test_compute_hash")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_compute_hash: {e}")
        failed += 1
    
    # Тест 3: Хеш-цепочка
    try:
        h1 = crypto_service.compute_hash_chain("ctx1", None)
        h2 = crypto_service.compute_hash_chain("ctx2", h1)
        assert h1 != h2
        print("[PASS] test_hash_chain")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_hash_chain: {e}")
        failed += 1
    
    # Тест 4: Подпись и верификация
    try:
        pk, pubk = crypto_service.generate_key_pair()
        ctx = {'id': '1', 'user_id': 'u1', 'content': 'test', 'created_at': '2026-01-01'}
        sig = crypto_service.sign_context(pk, ctx)
        valid = crypto_service.verify_signature(pubk, sig, ctx)
        assert valid == True
        print("[PASS] test_sign_and_verify")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_sign_and_verify: {e}")
        failed += 1
    
    # Тест 5: Обнаружение tampering
    try:
        content = "original"
        h = crypto_service.compute_hash(content)
        tampered = "modified"
        detected = security_service.detect_tampering(tampered, h, None)
        assert detected == True
        print("[PASS] test_detect_tampering")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_detect_tampering: {e}")
        failed += 1
    
    # Тест 6: Обнаружение replay атаки
    try:
        old = "2020-01-01T00:00:00"
        detected = security_service.detect_replay_attack(old)
        assert detected == True
        print("[PASS] test_detect_replay_attack")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_detect_replay_attack: {e}")
        failed += 1
    
    # Тест 7: Проверка script injection
    try:
        result = security_service.check_suspicious_content("<script>")
        assert 'script_injection' in result
        print("[PASS] test_script_injection_detection")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_script_injection_detection: {e}")
        failed += 1
    
    # Тест 8: Проверка prompt injection
    try:
        result = security_service.check_suspicious_content("ignore previous instructions")
        assert 'prompt_injection' in result
        print("[PASS] test_prompt_injection_detection")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_prompt_injection_detection: {e}")
        failed += 1
    
    # Тест 9: Trust Score расчёт
    try:
        calc = TrustScoreCalculator()
        result = {'signature_valid': True, 'hash_chain_valid': True, 
                  'timestamp_fresh': True, 'tampering_detected': False, 
                  'source_trusted': True}
        score = calc.calculate({}, result)
        assert score == 1.0
        print("[PASS] test_trust_score_calculation")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_trust_score_calculation: {e}")
        failed += 1
    
    # Тест 10: Классификация ACCEPT
    try:
        calc = TrustScoreCalculator()
        assert calc.classify(0.8) == "ACCEPT"
        assert calc.classify(0.7) == "ACCEPT"
        print("[PASS] test_classify_accept")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_classify_accept: {e}")
        failed += 1
    
    # Тест 11: Классификация QUARANTINE
    try:
        calc = TrustScoreCalculator()
        assert calc.classify(0.5) == "QUARANTINE"
        assert calc.classify(0.4) == "QUARANTINE"
        print("[PASS] test_classify_quarantine")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_classify_quarantine: {e}")
        failed += 1
    
    # Тест 12: Классификация REJECT
    try:
        calc = TrustScoreCalculator()
        assert calc.classify(0.3) == "REJECT"
        assert calc.classify(0.0) == "REJECT"
        print("[PASS] test_classify_reject")
        passed += 1
    except Exception as e:
        print(f"[FAIL] test_classify_reject: {e}")
        failed += 1
    
    print("=" * 60)
    print(f"РЕЗУЛЬТАТЫ: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0

if __name__ == "__main__":
    success = test_all()
    sys.exit(0 if success else 1)
