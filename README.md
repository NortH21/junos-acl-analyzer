# junos-acl-analyzer
<a target="_blank" href="https://hub.docker.com/r/north21/junos-acl-analyzer"><img src="https://img.shields.io/docker/pulls/north21/junos-acl-analyzer" /></a>
<a target="_blank" href="https://hub.docker.com/r/north21/junos-acl-analyzer/tags"><img src="https://img.shields.io/docker/v/north21/junos-acl-analyzer/latest?label=docker%20image%20ver." /></a>

### Run
```
LATEST_TAG=$(curl -s "https://hub.docker.com/v2/repositories/north21/junos-acl-analyzer/tags/?ordering=last_updated" | jq -r '.results[0].name')

docker run -d \
  --pull=always \
  -p 8080:8080 \
  -v /path_to_repo/jcore-filters:/app/jcore-filters \
  --name junos-acl-analyzer \
  -e JIRA_URL="https://jira.example.com/browse/" \
  -e NETBOX_URL="https://netbox.example.com/search/?q=" \
  north21/junos-acl-analyzer:${LATEST_TAG}
```

#### Переменные окружения
| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `JIRA_URL` | `https://jira.example.com/browse/` | Префикс ссылки на задачу (запросы вида `NOC-123`) |
| `NETBOX_URL` | `https://netbox.example.com/search/?q=` | Префикс ссылки на поиск в Netbox |
| `LISTEN_ADDR` | `:8080` | Адрес и порт, на которых слушает сервер |
| `FILTERS_DIR` | `./jcore-filters` | Каталог с файлами фильтров. Может быть символической ссылкой, которую переключает `git-sync` |
| `RELOAD_INTERVAL` | `2m` | Как часто проверять файлы фильтров (`30s`, `2m`). Без изменений проверка занимает миллисекунды |
| `LOG_LEVEL` | `info` | Уровень логов: `debug`, `info`, `warn`, `error` |
| `TRUSTED_PROXIES` | пусто | Адреса и сети ingress через запятую. Только от них принимается `X-Forwarded-For` для поля `remote_addr` |

#### Запуск в Kubernetes
Манифестов в репозитории нет, ниже требования к поду.

**Контейнер сервиса**

| Что | Значение |
| --- | --- |
| Образ | `north21/junos-acl-analyzer:latest` или `ghcr.io/north21/junos-acl-analyzer:latest` |
| Порт | `8080` (HTTP): интерфейс, пробы и метрики |
| Liveness | `GET /healthz` - `200`, пока процесс отвечает на запросы |
| Readiness | `GET /readyz` - `200`, когда фильтры загружены; `503`, пока данных нет |
| Метрики | `GET /metrics` в формате Prometheus |
| Остановка | по `SIGTERM` дожидается текущих запросов до 20 секунд и выходит с кодом 0 |
| Пользователь | `1000:1000`, запись на диск не нужна (`readOnlyRootFilesystem: true`) |
| Память | запрос `256Mi`, лимит `512Mi`, переменная `GOMEMLIMIT=400MiB` |

Переменные для кластера:
```
FILTERS_DIR=/data/jcore-filters
RELOAD_INTERVAL=30s
GOMEMLIMIT=400MiB
TRUSTED_PROXIES=<сети подов ingress>
JIRA_URL=...
NETBOX_URL=...
```

- `GOMEMLIMIT` нужен, потому что Go не знает о лимите контейнера. Данные занимают около 70 МБ; когда фильтры меняются, на время разбора в памяти лежат старая и новая копии, а страницы с сотнями правил собираются в памяти целиком.
- После неудачной перезагрузки сервис работает на прежних данных и остается готовым.
- `terminationGracePeriodSeconds` должен быть больше 20 секунд (подойдет значение по умолчанию, 30). Чтобы запросы не приходили в уже останавливающийся под, добавьте `preStop` с паузой в несколько секунд: `sleep` в образе есть.
- `/metrics` отдается на основном порту. Prometheus и пробы ходят в под напрямую; если показывать метрики пользователям не нужно, закройте путь на ingress.
- Логи собираются только из разрешенных namespace (см. правила логирования).

**Фильтры: sidecar git-sync**

Сервис сам в git не ходит. Рядом с ним работает контейнер [git-sync](https://github.com/kubernetes/git-sync), который клонирует репозиторий с фильтрами в общий том и атомарно переключает ссылку на новую версию. Сервис читает том только на чтение.

| Что | Значение |
| --- | --- |
| Общий том | `emptyDir`, смонтирован в оба контейнера в `/data`; в сервисе - `readOnly` |
| Репозиторий | HTTPS-адрес репозитория с фильтрами, ветка `master` |
| Доступ | токен только на чтение из `Secret`, передается файлом |
| Глубина | `1` - история репозитория занимает сотни мегабайт, нужна только последняя версия |
| Период опроса | `60s` |
| Каталог и ссылка | корень `/data`, ссылка `jcore-filters` - получится `/data/jcore-filters` |
| Размер тома | рабочая копия с неглубокой историей занимает порядка 50 МБ |

Параметры для git-sync v4 (сверьте с документацией вашей версии, имена флагов между версиями менялись):
```
--repo=https://<git-сервер>/<группа>/jcore-filters.git
--ref=master
--depth=1
--period=60s
--root=/data
--link=jcore-filters
--username=<имя токена>
--password-file=/etc/git-secret/token
```

- Запустите git-sync еще и как init-контейнер с `--one-time`: тогда к старту сервиса данные уже на месте. Без этого `/readyz` отвечает `503`, пока не пройдет первый клон и следующая проверка файлов.
- Изменения доходят до сервиса за период опроса git-sync плюс `RELOAD_INTERVAL`, то есть примерно за полторы минуты.
- Новый коммит без изменений в файлах фильтров сервис не перечитывает: он сравнивает содержимое файлов, а не каталог версии.
- В подвале страниц и в метрике `junos_acl_analyzer_data_changed_timestamp_seconds` видно, когда под последний раз загрузил изменившиеся данные. После перезапуска пода это время перезапуска.

**Метрики**

| Метрика | Что показывает |
| --- | --- |
| `junos_acl_analyzer_rules`, `..._prefix_lists`, `..._filter_files` | объем загруженных данных |
| `junos_acl_analyzer_data_changed_timestamp_seconds` | когда данные последний раз менялись (0 - не загружены) |
| `junos_acl_analyzer_last_reload_success_timestamp_seconds` | последняя успешная проверка файлов |
| `junos_acl_analyzer_reloads_total{result}` | проверки файлов: `changed`, `unchanged`, `error` |
| `junos_acl_analyzer_unparsed_values{kind}` | значения, которые не удалось разобрать |
| `junos_acl_analyzer_http_requests_total{route,code}` | запросы по маршруту и коду ответа |
| `junos_acl_analyzer_http_request_duration_seconds_total{route}` | суммарное время обработки |
| `junos_acl_analyzer_memory_*`, `..._goroutines`, `..._gc_cycles_total` | состояние процесса |

Полезные алерты: `time() - junos_acl_analyzer_last_reload_success_timestamp_seconds > 600` (сервис не может прочитать файлы) и рост `junos_acl_analyzer_reloads_total{result="error"}`. Остановку самого git-sync сервис не видит - для нее нужны метрики git-sync.

#### Логи
Одно событие - одна строка JSON в stdout, время в UTC:
```json
{"time":"2026-10-08T18:58:22.566Z","level":"info","msg":"GET /check -> 200 in 23ms","app":"junos-acl-analyzer","component":"http","request_id":"a57715016152c37941cc769df82ecec9","remote_addr":"203.0.113.9","method":"GET","path":"/check","status":200,"duration_ms":23,"src":"10.237.241.14","port":"443","result":"open","matches":198}
```

- `component` - подсистема: `server` (запуск), `loader` (чтение фильтров), `http` (запросы).
- На каждый запрос пишется одна строка; успешные запросы статики, проб Kubernetes и метрик не пишутся.
- Что искали и проверяли, лежит в полях `query`, `src`, `dst`, `port`, `filter`; итог проверки - в `result` (`open`, `partial`, `denied`, `invalid`).
- `request_id` берется из заголовка `X-Request-Id` или создается и возвращается в ответе.
- Перезагрузка фильтров раз в две минуты попадает в лог, только если данные изменились или случилась ошибка (на уровне `debug` видна каждая).
- Предупреждения о значениях, которые не удалось разобрать (поле `problem`), пишутся при старте и при изменении набора таких значений.
- В тексте `msg` нет IP-адресов: сборщик логов записал бы первый из них в `remote_addr`. Адреса всегда в отдельных полях.

#### Как работает поиск
- Адрес без маски (`192.168.244.178`) находит все правила с сетями, в которые он входит.
- Адрес или сеть с маской (`192.168.244.178/32`, `10.237.241.0/24`) находит только правила, где записан именно этот префикс.
- Неполный адрес (`10.237.`) ищется по началу префикса, остальное - по имени prefix-list и терма.

#### Как работает проверка доступа
Каждый фильтр проверяется отдельно и по порядку термов, как в Junos: первый подошедший терм решает судьбу трафика, в конце фильтра действует неявный discard.

- **ACCESS OPEN** - есть разрешающий терм, перед которым нет подходящих запретов.
- **ACCESS PARTIALLY OPEN** - разрешающий терм есть, но выше по фильтру стоит запрет, который может перехватить часть трафика (он указан в карточке правила).
- **ACCESS DENIED** - разрешающих термов нет; если запрос целиком попал под запрещающий терм, он будет показан.

Пустое поле означает "любое значение". Протокол, source-port и прочие условия в запросе не задаются, поэтому показываются в карточке как дополнительные условия правила.

#### Разработка
```
go vet ./...
go test -race ./...
```

#### Обновление правил
Файлы перечитывает сам раз в пару минут, но репу надо обновлять отдельно. Можно добавить в крон.
Обычно в рабочий день репа обновляется 2-6 раз в сутки.
```
crontab -l
0 10-19 * * 1-5 cd /path_to_repo/jcore-filters; git pull >> ~/cron.log 2>&1
```
