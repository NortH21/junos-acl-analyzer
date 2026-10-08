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
0 11-18 * * 1-5 cd /path_to_repo/jcore-filters; git pull >> ~/cron.log 2>&1
```
