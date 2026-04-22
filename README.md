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
  -e JIRA_URL="https://jira.example.com/browse/"
  -e NETBOX_URL="https://netbox.example.com/search/?q="
  north21/junos-acl-analyzer:${LATEST_TAG}
```

#### Обновление правил
Файлы перечитывает сам раз в пару минут, но репу надо обновлять отдельно. Можно добавить в крон.
Обычно в рабочий день репа обновляется 2-6 раз в сутки.
```
crontab -l
0 10-19 * * 1-5 cd /path_to_repo/jcore-filters; git pull >> ~/cron.log 2>&1
```
