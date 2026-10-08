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
| `LOG_LEVEL` | `info` | Уровень логов: `debug`, `info`, `warn`, `error` |
| `TRUSTED_PROXIES` | пусто | Адреса и сети ingress через запятую. Только от них принимается `X-Forwarded-For` для поля `remote_addr` |

#### Пробы Kubernetes
| Путь | Ответ |
| --- | --- |
| `/healthz` | `200`, пока процесс отвечает на запросы (liveness) |
| `/readyz` | `200`, когда фильтры загружены; `503`, пока данных нет (readiness) |

После неудачной перезагрузки сервис продолжает работать на прежних данных и остается готовым.

#### Логи
Одно событие - одна строка JSON в stdout, время в UTC:
```json
{"time":"2026-10-08T18:58:22.566Z","level":"info","msg":"GET /check -> 200 in 23ms","app":"junos-acl-analyzer","component":"http","request_id":"a57715016152c37941cc769df82ecec9","remote_addr":"203.0.113.9","method":"GET","path":"/check","status":200,"duration_ms":23,"src":"10.237.241.14","port":"443","result":"open","matches":198}
```

- `component` - подсистема: `server` (запуск), `loader` (чтение фильтров), `http` (запросы).
- На каждый запрос пишется одна строка; успешные запросы статики и проб Kubernetes не пишутся.
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
