# junos-acl-analyzer
<a target="_blank" href="https://hub.docker.com/r/north21/junos-acl-analyzer"><img src="https://img.shields.io/docker/pulls/north21/junos-acl-analyzer" /></a>
<a target="_blank" href="https://hub.docker.com/r/north21/junos-acl-analyzer/tags"><img src="https://img.shields.io/docker/v/north21/junos-acl-analyzer/latest?label=docker%20image%20ver." /></a>

### Run
```
docker run -d --pull=always -p 8080:8080 -v /path_to_repo/jcore-filters:/app/jcore-filters --name junos-acl-analyzer north21/junos-acl-analyzer:latest
```

#### Обновление правил
Файлы перечитывает сам раз в пару минут, но репу надо обновлять отдельно. Можно добавить в крон.
Обычно в рабочий день репа обновляется 2-6 раз в сутки.
```
crontab -l
0 11-18 * * 1-5 cd /path_to_repo/jcore-filters; git pull >> ~/cron.log 2>&1
```
