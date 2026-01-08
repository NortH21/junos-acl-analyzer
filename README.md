# junos-acl-analyzer

### Run
```
docker run -d --pull=always -p 8080:8080 -v /path_to_repo/jcore-filters:/app/jcore-filters --name junos-acl-analyzer north21/junos-acl-analyzer:latest
```

#### Обновление правил
Файлы перечитывает сам раз в пару минут, но репу надо обновлять отдельно. Можно добавить в крон.
Обычный в рабочий день репа обновляется 2-6 раз в сутки.
```
crontab -l
0 11-18 * * 1-5 cd /path_to_repo/jcore-filters; git pull >> ~/cron.log 2>&1
```
