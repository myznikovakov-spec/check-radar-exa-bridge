# Check Radar — Access Checks Policy

Этот файл описывает, какие ситуации bridge должен считать проверкой доступа или защитой сайта.

## Базовые категории

1. CAPTCHA
2. Anti-bot challenge
3. Human verification
4. Access denied / blocked
5. Rate limit / too many requests
6. Temporary service protection
7. robots.txt restriction
8. Login / authentication required
9. Paywall / restricted content
10. JavaScript / browser verification challenge

## Базовое поведение

Если bridge встречает одну из этих проверок:

- не пытаться обходить защиту;
- не маскировать автоматическую активность;
- не выполнять агрессивные повторные запросы;
- остановить автоматический проход по этому источнику;
- пометить источник как требующий отдельной проверки;
- при сомнении выбирать безопасный вариант: STOP + ручная проверка.

## Принцип

Check Radar работает как вежливый crawler:
уважает ограничения сайта, не ломится через защиту и не провоцирует блокировку.

Этот файл пока содержит только правила поведения.
Детекторы и автоматическая логика добавляются отдельными маленькими патчами.
