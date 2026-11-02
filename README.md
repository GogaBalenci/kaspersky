# Threat Information Exchange Service

REST-сервис на Go для создания, получения и обновления обогащённой информации о файловых угрозах по MD5. API описан в [OpenAPI-спецификации](api/openapi.yaml); Go-модели и маршруты генерируются через `oapi-codegen`.

## Что реализовано

- `POST /info`, `GET /info/{md5}`, `PUT /info/{md5}`;
- PostgreSQL, встроенные версионируемые миграции и защита миграций от параллельного запуска;
- строгая валидация JSON и доменных правил, нормализация MD5 к lowercase;
- единый JSON-формат ошибок и корректные `400`, `401`, `404`, `409`, `429`, `500`;
- API key на операциях записи, rate limit по IP, request ID и структурированные JSON-логи;
- `/healthz`, проверяющий доступность PostgreSQL;
- unit- и интеграционные тесты с реальным PostgreSQL 16 в Testcontainers;
- multi-stage Dockerfile и Docker Compose.

## Быстрый запуск

### Docker Compose

Нужны Docker Desktop и `make`. Запуск одной командой:

```bash
make up
```

При первом запуске создаётся `.env` со случайными `API_KEY` и `POSTGRES_PASSWORD` (файл исключён из Git), затем собирается образ и поднимаются PostgreSQL и сервис. Команда завершается, когда сервис прошёл healthcheck, и печатает адрес и API key. Порт приложения публикуется только на `127.0.0.1:8080`.

```bash
make logs   # логи сервиса
make down   # остановить и удалить контейнеры, сеть, volume с данными и собранный образ
```

`make down` полностью подчищает окружение, поэтому данные в БД удаляются. `.env` сохраняется, и следующий `make up` использует те же ключи. Без `make` можно запустить напрямую, задав секреты вручную: `API_KEY=... POSTGRES_PASSWORD=... docker compose up --build`.

### Локальный запуск

Нужны Go 1.26+ и PostgreSQL 16+.

```bash
cp .env.example .env
# Укажите реальный DATABASE_URL и сгенерированный API_KEY в .env.
set -a && source .env && set +a
make run
```

`.env` исключён из Git. Не используйте примерный или короткий API key вне локальной разработки.

## Конфигурация

| Переменная | Обязательна | По умолчанию | Назначение |
| --- | --- | --- | --- |
| `DATABASE_URL` | да | — | Строка подключения PostgreSQL |
| `API_KEY` | да | — | Секрет заголовка `X-API-Key` для `POST` и `PUT` |
| `HTTP_ADDRESS` | нет | `:8080` | Адрес HTTP-сервера |
| `RATE_LIMIT_PER_MINUTE` | нет | `60` | Запросов с одного IP в минуту |
| `RATE_LIMIT_BURST` | нет | `10` | Допустимый кратковременный burst |
| `REQUIRE_API_KEY_FOR_READS` | нет | `false` | Требовать `X-API-Key` и для `GET /info/{md5}` |
| `REQUEST_TIMEOUT` | нет | `5s` | Лимит времени на обработку запроса, включая запросы к БД; меньше write timeout `15s` |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | нет | — | Пути к сертификату и ключу; если заданы оба, сервер работает по HTTPS (TLS 1.2+) |
| `POSTGRES_PASSWORD` | да, для Compose | — | Пароль PostgreSQL в Docker Compose |
| `DB_MAX_CONNS` | нет | `10` | Максимальный размер пула PostgreSQL |
| `DB_MIN_CONNS` | нет | `1` | Минимальный размер пула |
| `DB_MAX_CONN_LIFETIME` | нет | `1h` | Максимальная жизнь соединения |
| `DB_MAX_CONN_IDLE_TIME` | нет | `30m` | Максимальный простой соединения |
| `DB_HEALTH_CHECK_PERIOD` | нет | `1m` | Период healthcheck пула |

## API и примеры

Полный контракт, ограничения полей и схемы ответов находятся в [api/openapi.yaml](api/openapi.yaml).

| Метод | Путь | Авторизация | Назначение |
| --- | --- | --- | --- |
| `GET` | `/healthz` | нет | Проверить сервис и БД |
| `GET` | `/info/{md5}` | нет, либо `X-API-Key` при `REQUIRE_API_KEY_FOR_READS=true` | Получить угрозу |
| `POST` | `/info` | `X-API-Key` | Создать угрозу |
| `PUT` | `/info/{md5}` | `X-API-Key` | Заменить изменяемые поля угрозы |

Создание:

```bash
curl --request POST http://localhost:8080/info \
  --header 'Content-Type: application/json' \
  --header "X-API-Key: $API_KEY" \
  --data '{
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "name": "Trojan.Win32.Generic",
    "type": "trojan",
    "severity": "high",
    "description": "Credential-stealing trojan",
    "tags": ["windows", "stealer"]
  }'
```

Получение:

```bash
curl http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

Обновление:

```bash
curl --request PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  --header 'Content-Type: application/json' \
  --header "X-API-Key: $API_KEY" \
  --data '{
    "name": "Ransom.Win32.Example",
    "type": "ransomware",
    "severity": "critical",
    "tags": ["windows", "encryptor"]
  }'
```

Все ошибки, включая неизвестный путь (`404`), неподдерживаемый метод (`405`) и некорректный параметр пути, имеют единый вид:

```json
{"message":"invalid request","details":"md5: must contain exactly 32 hexadecimal characters"}
```

## Модель угрозы

| Поле | Смысл |
| --- | --- |
| `md5` | Уникальный MD5 файла; сервис хранит его в lowercase |
| `name` | Имя детекта |
| `type` | `trojan`, `ransomware`, `worm`, `adware`, `spyware` или `other`; необязательное, по умолчанию `other` |
| `severity` | `low`, `medium`, `high` или `critical`; необязательное, по умолчанию `medium` |
| `description` | Необязательное описание до 4 000 символов |
| `tags` | До 20 уникальных тегов |
| `first_seen_at`, `last_seen_at` | Необязательные времена обнаружения в диапазоне от `1970-01-01T00:00:00Z` до «сейчас + 24 часа»; первое не позднее второго |
| `created_at`, `updated_at` | Серверные timestamps |

Обязательны, как и в исходном контракте, только `md5` и `name` для `POST` и `name` для `PUT`. `PUT` заменяет запись целиком: пропущенные необязательные поля сбрасываются к значениям по умолчанию. Тело запроса должно быть валидным UTF-8. `name` и теги не могут содержать управляющие символы (NUL, перевод строки, escape-последовательности); в `description` переводы строк допустимы, NUL нет. Пустое `description` сохраняется как отсутствующее. Все timestamps в ответах возвращаются в UTC.

Критичные ограничения дублируются в PostgreSQL: формат MD5, enum-значения, порядок дат, непустое имя и лимит тегов.

## Архитектура

```text
OpenAPI → generated Go types/router → HTTP handler → service → repository → PostgreSQL
                                             │                         ↑
                                  auth, rate limit, logs, IDs      migrations
```

- `internal/transport/http` — HTTP, middleware и преобразование JSON;
- `internal/service` — нормализация и бизнес-валидация;
- `internal/repository/postgres` — SQL и отображение ошибок PostgreSQL;
- `migrations` — встроенные SQL-миграции с advisory lock;
- `cmd/server` — composition root, graceful shutdown и HTTP timeouts.

## Команды и тестирование

```bash
make generate # пересоздать Go-код из OpenAPI
make up      # запустить в Docker
make down    # остановить и подчистить Docker-окружение
make test     # unit- и интеграционные тесты
make test-race        # то же с race detector
make test-integration # интеграционные тесты с подробным выводом (виден skip)
make lint     # go vet ./...
make run      # локальный запуск
go build ./... # проверить сборку всех пакетов
```

Интеграционный тест поднимает PostgreSQL 16 через Testcontainers. Если Docker недоступен, этот тест будет skipped, а unit-тесты продолжат выполняться. Без Docker его можно запустить на отдельной одноразовой базе:

```bash
INTEGRATION_DATABASE_URL='postgres://user:pass@localhost:5432/threats_test?sslmode=disable' go test ./tests/integration/...
```

## Осознанные компромиссы

- Rate limit считается по адресу TCP-соединения (`RemoteAddr`). За reverse proxy или Docker Desktop все клиенты видны с одного адреса и делят общий лимит; заголовки `X-Forwarded-For` намеренно не учитываются, потому что без списка доверенных прокси их легко подделать. В таком окружении лимит лучше ставить на прокси. Таблица клиентов ограничена 100 000 записей.
- Rate limit хранится в памяти процесса. Для горизонтально масштабируемого production-кластера его следует вынести в Redis или поставить лимит на API gateway.
- TLS можно включить в самом приложении (`TLS_CERT_FILE`/`TLS_KEY_FILE`), но в production сертификаты обычно завершаются на ingress или reverse proxy. Соединение с PostgreSQL в Compose идёт без TLS только внутри приватной сети Compose; для внешней БД используйте `sslmode=verify-full`.
- Реализован ровно требуемый контракт без удаления и списка угроз. Их можно добавить отдельной версией OpenAPI, не обещая недоделанные endpoints.
