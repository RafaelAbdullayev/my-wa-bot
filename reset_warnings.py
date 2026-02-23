# reset_warnings.py - Сброс всех предупреждений
import json

# Очищаем файл предупреждений
with open('warnings.json', 'w') as f:
    json.dump({}, f)

print("✅ Все предупреждения сброшены!")