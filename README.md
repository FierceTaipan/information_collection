Пассивный/Активный сбор информации:
```
Узнаем IP
Whois
DNS
Сканируем порты
Хостинг
Reverse-IP
SEO-параметры
Веб-архив
Поисковые системы
Блек-листы

```
```
1. Узнаем IP
ping target.com

Если ресурс большой, было бы неплохо проверить его на сервисе вроде ping-admin.ru.
Вполне может быть, что у ресурса IP не один, а сразу несколько

Узнать IP адрес сайта
host -t A example.com

Сервис для получения всех ip адресов, принадлежащих одному хосту, доменному имени или сайту.
https://ciox.ru/get_all_ip_address_of_host

IP range Crawl
https://bgp.he.net/
```
```
2. Whois. После того, как мы узнали IP адрес домена, воспользуемся сервисом whois, чтобы узнать немного дополнительной информации.

whois target.com

Можно увидеть страну и провайдера, которому принадлежит IP адрес. Помимо этого, можем увидеть некоторые дополнительные данные, а так же можем увидеть ns-записи(информацию о DNS-сервере для данного домена). Чаще всего они прямо указывают на хостинг сайта. Иногда - на проксирующий сервис. Иногда на сам домен, что позволяет заключить, что сайт находиться на выделенном сервере.

Сервисы для проверки whois:
http://whoer.net/
https://www.nic.ru/whois/
http://www.whois-service.ru/
https://who.is/
http://whois.domaintools.com/
http://r01.ru/domain/whois/
https://www.reg.ru/whois/

В поле inetnum указывается диапазон IP адресов, принадлежащих компании
inetnum 95.200.118.0 - 95.200.119.255

Есть замечательный сервис: Благодаря ему, можем узнать, как изменялись данные whois
http://www.whoishistory.ru/. 
https://whoisrequest.com/history/
https://www.whoxy.com/

2.1 SSL-сертификаты, используемые сервером, могут содержать информацию о других доменных именах, для которых действителен данный сертификат. https://crt.sh/

2.2 Поиск «живых» хостов
Если повезло, получили пул адресов, которые принадлежат объекту. Найдем какие используются в данный момент.

fping -Asg 95.200.118.0/24 -r 2 >> adress.list
cat address.list | grep alive

```
```
3. Проверяем dns-записи. Существует большое количество самых разных видов DNS-записей (A, MX, NS, CNAME, SOA, SRV, PTR, RP, HINFO). Нам нужно узнать поддомены сайта - увеличить количество целей для атаки, и следовательно увеличить шансы взлома.

DNS-резолвер
Это компьютеры, которые провайдеры используют для поиска в их базе данных конкретного узла, запрашиваемого пользователем. Когда данные получены, пользователь перенаправляется на соответствующий IP-адрес.
DNS-резолвер кэширует информацию. Время, в течение которого запись хранится в резолвере, называется TTL (time to live).

Корневой DNS-сервер
Это DNS-сервер, который хранит в себе адреса всех TLD-серверов (TLD — top-level domain, домен верхнего уровня). По пути от имени хоста до IP-адреса запрос сначала попадает на корневой DNS-сервер.

TLD-серверы
Эти серверы связаны с доменами верхнего уровня (TLD). В TLD-серверах содержится информация о домене верхнего уровня конкретного хоста. TLD-сервер возвращает адрес авторитативного DNS-сервера для резолвера.

Авторитативный DNS-сервер
Запрос на эти серверы поступает в самую последнюю очередь. Эти серверы хранят фактические записи типа A, NS, CNAME, TXT... Авторитативные DNS-серверы по возможности возвращают IP-адреса хостов. Если сервер этого сделать не может — он выдаёт ошибку, и на этом поиск IP-адреса по серверам заканчивается.

Существует 3 типа DNS-запросов:
* Рекурсивный: подобные запросы выполняют пользователи к резолверу. Собственно, это первый запрос, который выполняется в процессе DNS-поиска. Резолвером чаще всего выступает ваш интернет провайдер или сетевой администратор.
* Нерекурсивные: в нерекурсивных запросах резолвер сразу возвращает ответ без каких-либо дополнительных запросов на другие сервера имён. Это случается, если в локальном DNS-сервере закэширован необходимый IP-адрес либо если запросы поступают напрямую на авторитативные серверы, что позволяет избежать рекурсивных запросов.
* Итеративный: итеративные запросы выполняются, когда резолвер не может вернуть ответ, потому что он не закэширован. Поэтому он выполняет запрос на корневой DNS-сервер. А тот уже знает, где найти фактический TLD-сервер

Чтобы узнать поддомены, можно воспользоваться запросом в гугл вида:
site:*.target.com
Все ссылки в выдаче будут вести на поддомены, не закрытые от индексации.

A и AAAA записи, содержащие IP-адреса для данного доменного имени, во-вторых, MX, SOA, SRV, NS записи, которые могут содержать информацию о дополнительных доменах, а также TXT, которая содержит произвольные данные, например, там размещаются так называемые SPF-записи.

Но, чтобы получить все dns-записи, мы спросим все что нам надо у DNS-серверов. Есть такая штука, под названием передача зоны DNS (AXRF). Нужно это для того, чтобы DNS сервера поддерживали в актуальном состоянии свои базы. Т.е. отправили AXRF-запрос, получили все DNS-записи. В нормальном режиме это полезная штука, но когда DNS-сервер отвечает всем подряд без разбора, это уже несекьюрно.
dig -t AXFR target.com @ns.target.com

Онлайн-сервисы:

http://sergeybelove.ru/tools/axfr-test/?domain=
https://www.ultratools.com/tools/dnsLookupResult
http://hackertarget.com/zone-transfer/
https://viewdns.info/
https://dnstable.com

В случае успеха, мы получаем все DNS-записи: axrf

Разумеется, это не всегда получится (не все dns-сервера отдают инфу кому попало), да и не у всех сайтов вообще есть поддомены. Если не получилось узнать с помощью AXRF, стоит воспользоваться брутфорсером поддоменов.
https://code.google.com/p/dns-discovery/

Для получения информации о записях домена:
nslookup target.com
nslookup -query=mx(ns/soa/any) target.com
nslookup -debug target.com

Далее посмотрим как проходят пакеты до сервера.
traceroute имя_или_IP

В будущем, отправляя TCP, UDP, ICMP и GRE пакеты на разные порты, можно будет проанализировать где могут стоять пакетные фильтры.

recon-ng - разведывательный фреймворк, предназначен для обнаружения поддоменов, файлов с приватными данными, перебора пользователей, парсинга соцсетей, и так далее.
https://bitbucket.org/LaNMaSteR53/recon-ng.git
https://github.com/Raikia/Recon-NG-API-Key-Creation/blob/master/README-v4.8.3.md

git clone https://LaNMaSteR53@bitbucket.org/LaNMaSteR53/recon-ng.git
cd recon-ng
pip install -r REQUIREMENTS
./recon-ng

use recon/domains-hosts/brute_hosts
set SOURCE domain.com
run

Модули recon
(recon/domains-hosts/bing_domain_api
recon/domains-hosts/bing_domain_web
recon/domains-hosts/google_site_api
recon/domains-hosts/google_site_web
recon/domains-hosts/shodan_hostname)

Еще варианты обнаружения доменов, IP-адресов. 
В случае с Cloudflare может пригодиться этот ресурс - www.crimeflare.com, также на форуме exploit.in мелькала услуга определения реального IP, которая выполняется какими-то альтернативными методами. Если веб-сайт обладает формой, где предполагается указать свой e-mail адрес, чтобы впоследствии получить на него письмо, то это тоже может помочь в виду возможного раскрытия IP в служебных заголовках.
Пример - Received: from target.io (target.io [188.226.181.78])

Иногда сайт содержит некоторую логику, которая предполагает совершение HTTP/DNS/каких-либо еще запросов к заданным сайтам (например, если требуется подтвердить владение сайтом путем размещения на нем файла или путем создания дополнительной записи в DNS, что впоследствии проверяется). Может помочь публично доступный скрипт, содержащий phpinfo или страница server-status, но это уже можно отнести к уязвимостям.

Анализ DNS записей MX и SPF
Получить назначенные домену MX и SPF записи можно командами:
nslookup -type=mx TARGET.HOST
nslookup -type=txt TARGET.HOST

Ещё как вариант можно опросить ДНС-сервера доменного регистратора, ведь обычно при переключении ДНС-серверов на Cloudflare записи на ДНС-серверах доменного регистратора не удаляются, - сделать это можно командой: nslookup TARGET.HOST TARGET.NS

Использование разного рода сканеров
$ sudo apt-get install websploit
$ websploit

wsf > show modules
wsf > use web/cloudflare_resolver
wsf:CloudFlare Resolver > show options

wsf:CloudFlare Resolver > set Target TARGET.HOST
TARGET => TARGET.HOST
wsf:CloudFlare Resolver > run

Примерно того же результата можно достичь выполнив # nmap --script dns-brute -sn TARGET.HOST
```
```
4. Сканируем порты. Получив большой список поддоменов, IP, мы натравливаем сканер портов, например nmap:
И разумеется не только в дефолтном режиме.
Мы должны определить все открытые порты, сервисы, ОС.
Если нет желания палить собственный IP, или лень разбираться с nmap то можно воспользоваться сервисами:

http://hideme.ru/ports/
https://pentest-tools.com/discovery-probing/tcp-port-scanner-online-nmap
http://nmap.online-domain-tools.com/

Возможно найдется рабочий эксплоит под какой-то из сервисов/демонов, может быть сможем сбрутить ftp, ssh, rdp, и тогда даже не нужно будет возиться с веб-приложением. В любом случае — чем больше информации о цели, тем проще найти лазейку.

Быстрая проверка стандартных портов (sS означает “тихую” проверку)
nmap -sS «ip адрес или подсеть»

Проверка всех портов
nmap -sS «ip адрес или подсеть» -p1-65536

Определение версии ОС nmap -O «ip адрес или подсеть»
Определение версии сервисов: nmap -sV «ip адрес или подсеть»

Проверим, работает ли фаерволл на стороне жертвы:
nmap -sA «ip адрес или подсеть»

Если фаерволл стоит, попробуем сканировать через него:
nmap -PN «ip адрес или подсеть»

Команда обманет фаервол и заставит отправить ответ:
nmap -sN «ip адрес или подсеть»

TCP Fin сканирование для проверки брандмауэра. Устанавливает TCP FIN бит:
nmap -sF «ip адрес или подсеть»

Сканируем сеть с целью определить какие серверы и устройства запущены и работают:
nmap -sP «ip адрес или подсеть»

Сканирует порты в диапазоне:
nmap -p 80-200 «ip адрес или подсеть»

Следующая команда сканирует адреса на предмет версий служб плюс на открытые TCP порты:
nmap -p 1-65535 -sV -sS -T4 «ip адрес или подсеть»

Используем случайный MAC адрес. Цифра 0 означает, что nmap выбирает абсолютно случайный MAC адрес:
nmap -v -sT -PN --spoof-mac 0 «ip адрес или подсеть»

КАЖДОМ ИЗ ТИПОВ СКАНИРОВАНИЯ использовать обнулённый пинг, добавив в команду nmap флаг -P0. Если уж нам понадобилось пропинговать цель перед сканированием.

Запрещаем реверс DNS с помощью флага -n

Команды nmap для скрытого сканирования:
nmap -sS «ip адрес или подсеть»
nmap -sT «ip адрес или подсеть»
nmap -sA «ip адрес или подсеть»
nmap -sW «ip адрес или подсеть»
nmap -sM «ip адрес или подсеть»

Сканирует top порты:
nmap --top-ports 1000 -T4 -sC target.com

Сохранение результатов:
nmap «ip адрес или подсеть» > результаты.txt

Используйте Nmap + Tor + ProxyChains
sudo apt-get install tor
sudo apt-get install proxychains

ProxyChains по умолчанию уже настроен на работу с Tor.
В этом можно убедиться заглянув в /etc/proxychains.conf.
Последние строки конфига должны выглядеть следующим образом:
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 127.0.0.1 9050

Мы можем столкнуться с ситуацией когда сканирование не удается из-за того, что выходные ноды Tor-а попадают под блокировку (банятся сканируемым хостом).
Выходом из этой ситуации может быть добавление в ‘цепочку’ обыкновенного публичного прокси-сервера.
Это делается путем редактирования /etc/proxychains.conf и добавления новой записи в конце [ProxyList] (также убедитесь что опция random_chain отключена).

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050
socks4 115.71.237.212 1080
Новая ‘цепочка’ идет через Tor-прокси (127.0.0.1:9050) к указанному нами публичному прокси-серверу (115.71.237.212:1080), а затем к сканируемому хосту («ip адрес или подсеть»).

$ proxychains nmap -sT -PN -n -sV -p 80,443,21,22 «ip адрес или подсеть»

```
```
5. Хостинг.
Способы определения хостинга:
5.1. Домен третьего уровня (к примеру - target.freehosting.com, кто является хостером, очевидно).
5.2. Реклама на сайте. Частенько, фрихостинги пихают свою рекламу во все возможные места - popup, iframe, шапка, футер. В таком случае, определить хостинг не составляет труда.
5.3. 403/404. Пробуем открыть заведомо несуществующую страницу (вызвать ошибку 404). Или попытаемся  вызвать ошибку 403 -  пробуем зайти в папки /admin/, /images/ и т.д. Очень часто мы увидим заглушку от хостера.
5.4. index.html. При создании нового сайта в этом файле может находиться заглушка от хостера.
5.5. NS-записи. Изучая ns-записи, мы можем столкнуться с тремя ситуациями:

Сайт: target.com
ns-записи: ns1.hosting.com, ns2.hosting.com
Наиболее распространенный случай на shared хостингах. Хостингом является hosting.com.
Сайт: target.com
ns-записи: ns1.target.com, ns2.target.com
Владелец сайта использует свои собственные dns-сервера. Вероятно это VDS/DS.
Сайт: target.com
ns-записи: ns1.freedns.com, ns2.freedns.com
Владелец сайта использует сторонние dns-сервера. Вместо freedns.com может быть любой другой подобный сервис.

5.6. Проверяем данные по IP адресу. Смотрим на e-mail для контакта. Выглядят они как admin@superhost.com. Очевидно, что стоит смотреть на сайт superhost.com. Это может быть мыло как хостера, так и датацентра, где хостер арендует/держит серваки. В любом случае, хоть какая-то информация.
5.7. Заходим по IP адресу. Т.е. если Ip сайта - 123.123.23.23, мы вбиваем в браузере http://123.123.23.23/ и смотрим, что нам выдаст веб-сервер. У крупных хостеров стоит заглушка (по которой мы хостера резко и чотка опознаем). У мелких хостеров мы увидим либо вход в панель управления (ISP и подобные), либо один из сайтов, которые находятся на данном сервере.
5.8. Reverse DNS lookup. На линухе достаточно пингануть IP, на винде - использовать nslookup. Хостинг получается определить благодаря тому, что в PTR записях обычно используется название хостинга

Для получения тех же результатов можно воспользоваться одним из сервисов:
http://remote.12dt.com/lookup.php
http://mxtoolbox.com/ReverseLookup.aspx
http://www.dnswatch.info/
http://www.reverse-dns.org/
http://rdnslookup.com/
http://www.lookupserver.com/

5.9. Traceroute. Воспользуемся штатной утилитой traceroute
Благодаря трассировке, мы узнаем не только хостера, но и дата-центр. Или воспользуемся онлайн-сервисами:

http://traceroute.monitis.com/
http://www.ip-ping.ru/tracert/
http://russianproxy.ru/traceroute
http://centralops.net/co/

5.10. SMTP. Делаем коннект на 25 порт. Если там висит почтовый сервис, он нам сходу выдаст имя хоста (способ похож на предыдущие 2 - определяем хостинг по имени хоста).
Набираем:
telnet hostname/IP port

Команда telnet используется для интерактивного взаимодействия с другим хостом по протоколу TELNET. C помощью telnet мы можем проверить доступность порта на узле.

Или воспользуемся онлайн-сервисами:
http://www.adminkit.net/telnet.aspx
http://telnet.browseas.com/

Зачастую, в sendmail есть следующие баги:
a. (от кого письмо:)mail from : sendername|any_command_as_U_want  — возможность
выполнения любой UNIX команды
(теперь кому:)rcpt to : username|any_command_as_U_want — возможность
выполнения любой UNIX команды

b. rcpt to : /any_directory/any_filename — возможность
направить мессагу напрямую в файл

c. (сама мессага:)data — жмем Enter
здесь печатаем текст . для того чтобы закончить послание ставим .(точку) и жмем Enter

d. quit — выйти

«что это дает?» 
....
В первом случае можно сделать нечто типа: 
/bin/ls /var/spool/mail>/home/httpd/html/users_info.txt — получаем
список почтовых юзерей
/bin/cat /var/spool/mail/username>/home/httpd/html/user_box.txt —
получаем контент ящика юзера.
/bin/echo any_commands_here>>/etc/inetd.conf — добавляем
произвольные команды в конец инет демона.
/sbin/halt — паркуем сервак и т.д.

Во втором случае:
Можно дописать произвольные команды скажем в /etc/inetd.conf...

Проделав вышеописанные операции мы с вероятностью в 90% определим хостинг сайта. Исключение составят те случаи, когда IP сайта скрыт сервисами типа cloudflare или чем-то подобным.

Итак, что мы можем узнать, зная хостинг:
Виртуальный хостинг. Топаем на сайт хостера, изучаем сайт, изучаем форум, если он есть. Читаем FAQ. Можно даже оплатить аккаунт или взять тестовый, чтобы изучить хостинг вдоль и поперек. Смотрим, как происходит восстановление пароля, как происходит взаимодействие с техподдержкой. Работает ли ftp, ssh, что возможно сделать через панель хостера. Есть ли WAF. Какие настройки php (можно попросить показать вывод функции phpinfo()).
Узнаем, были ли взломы сайтов данного хостера. Если были, то как это происходило, есть ли дыры сейчас.
Если сайт находится на платформе типа ucoz, blogspot или подобных, то поиск уязвимостей на сайте равносилен поиску уязвимостей на самой платформе (что существенно усложняет задачу). Однако, есть плюс в том, что мы можем использовать методы социальной инженерии не только к владельцу сайта, но и к техподдержке хостинга.

VPS/VDS/DS. Если хостер так и не определен, то скорее всего мы имеем дело с выделенным сервером. В некоторых случаях это может быть арендованный сервер в дата-центре, может и домашний комп со белым IP, который не выключают сутками. Есть шанс, что админ выделенного сервера не настолько опытен, как админы крупных хостингов, и совершил ошибки при настройке сервера.
```
```
6. Reverse-IP. На одном IP и на одном сервере может находится множество сайтов:

Не существует 100% способа узнать все сайты на одном IP. Онлайн сервисы позволяют находить сайты на одном IP только благодаря большим базам (парсят денно и нощно). Поэтому необходимо использовать максимальное кол-во сервисов reverse-ip:

http://yougetsignal.com/tools/web-sites-on-web-server/
http://reverseip.domaintools.com/
http://ipaddress.com/reverse_ip/
http://viewdns.info/reverseip/
http://www.tcpiputils.com/domain-neighbors
http://ip-www.net/
http://www.ip-address.org/reverse-lookup/reverse-ip.php
http://bing.com/?q=ip:xxx.xxx.xxx.xxx

Сайты меняют хостинг, домены дропаются, поэтому полученные данные надо обязательно перепроверять. Если IP-адреса сайтов совпадают, можно утверждать, что они находятся на одном сервере. В некоторых случаях сайты могут находится на одном сервере, даже если у них различается последний октет IP адреса - 121.1.1.1, 121.1.1.2, 121.1.1.3.
```
```
7. SEO-параметры.
Узнаем основные seo-параметры сайта:
1. Тиц, Google Page Rank (PR), Яндекс-каталог, DMOZ.
2. Беклинки
3. Внешние ссылки.
```
```
8. Смотрим веб-архив. https://web.archive.org/
Мы можем найти контакты, которые уже убрали с сайта, можем найти информацию об ошибках, узнать насколько давно меняли сайт. Если сайт не менялся очень давно, есть шанс, что система давно не патчилась, и у нас больше шансов найти уязвимости.
waybackrobots 	https://gist.github.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07
waybackurls 	https://gist.github.com/mhmdiaa/adf6bff70142e5091792841d4b372050
```
```
Поисковые системы.
https://support.google.com/websearch/

Поиск папок открытых на просмотр:
site:target.com intitle:index.of
Поиск файлов с настройками:
site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini
Поиск файлов с бекапами БД:
site:target.com ext:sql | ext:dbf | ext:mdb
Поиск файлов с логами:
site:target.com ext:log
Поиск бекапов:
site:target.com ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
Поиск админки:
site:target.com inurl:login
Поиск ошибок, говорящих о SQL-инъекциях:
site:target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
Поиск документов:
site:target.com ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv
Поиск файла с phpinfo():
site:target.com ext:php intitle:phpinfo "published by the PHP Group"

Еще больше дорков
https://www.exploit-db.com/google-hacking-database

Проверка на virustotal/blacklist's. Вполне может быть, что раньше сайт/сервер ломали. И можно найти что-то интересное.
https://www.virustotal.com/gui/home/url
```

```
https://github.com/LionSec/katoolin - подключить репозитории Kali
```

WAF — важная часть безопасности веб-приложения. Фильтр, который в реальном времени блокирует вредоносные запросы еще до того, как они достигнут сайта.

```
Какие бывают WAF
По режиму работы:
• Мост/Маршрутизатор
• Обратный прокси-сервер
• Встроенный
По модели защиты:
• Основанный на сигнатуре (Signature-based)
• Основанный на правилах (Rule-based)
По реакции на «плохой» запрос:
• «Очистка опасных» данных
• Блокировка запроса
• Блокировка источника атаки

Механизмы работы WAF изнутри. Этапы обработки входящего трафика в большинстве WAF одинаковы. Условно можно выделить пять этапов:

1 Парсинг HTTP-пакета, который пришел от клиента.
2 Выбор правил в зависимости от типа входящего параметра.
3 Нормализация данных до вида, пригодного для анализа.
4 Применение правила детектирования.
5 Вынесение решения о вредоносности пакета. На этом этапе WAF либо обрывает соединение, либо пропускает дальше — на уровень приложения.

Методы обхода WAF
Фундаментальные ограничения технологии
• Неспособность полностью защитить Web-приложение от всех
возможных уязвимостей
Общие проблемы
• При использовании универсальных фильтров WAF приходится
балансировать между эффективностью фильтра и
минимизацией ошибок блокировки легитимного трафика
• Обработка возвращаемого трафика клиенту
Уязвимости реализации
• Технологии нормализации
• Использование новых техник эксплуатации уязвимостей в
Web (HTTP Parameter Pollution, HTTP Parameter Fragmentation,
замена null-byte, etc)

Если проанализировать виды логик обнаружения атак в пятнадцати наиболее популярных WAF, то лидировать будут:

регулярные выражения;
токенайзеры, лексические анализаторы;
репутация;
выявление аномалий;
score builder.

Регулярные выражения очень популярны в security-продуктах. При работе с веб-приложениями ты встретишь их на всех уровнях. Самый первый и ближайший к пользователю — XSS Auditor, который встроен во все популярные браузеры (даже в IE, начиная с версии 7). Второй — это фронтендовые анализаторы, предотвращающие исполнение вредоносного кода, который может прийти с бэкенда в качестве данных. Третий уровень — бэкенд, на котором также могут использоваться регулярки для постобработки данных — проверять пользовательский ввод перед сохранением в БД, а также перед выводом пользователю.

Модификаторы, числовые квантификаторы и позиционные указатели!
"/^(attackpayload){1,3}$/"
Символы начала и конца строки (^$). Выражение ищет вредоносную нагрузку, жестко привязываясь к позиции в строке. В большинстве языков, для которых предназначается вредоносная нагрузка (например, SQL), пробелы в начале и в конце строки не влияют на синтаксис. Таким образом, если добавить пробелы в начале и конце строки, защиту удастся обойти
Регистр. Выражение не учитывает регистр, поэтому, если использовать нагрузку разного регистра. Модификатор (?i), благодаря которому регистр не будет учитываться.
Квантификаторы ({1,3}). Регулярное выражение ищет количество вхождений от одного до трех. Соответственно, написав полезную нагрузку четыре или более раз, можно ее обойти.

Ошибки логики!
(a+)+ — это пример так называемого ReDoS, отказа в обслуживании при парсинге текста уязвимым регулярным выражением. Проблема в том, что это регулярное выражение будет обрабатываться парсером слишком долго из-за чрезмерного количества вхождений в строку. То есть если мы передадим aaaaaaa....aaaaaaaab, то в некоторых парсерах такой поиск будет выполнять 2^n операций сравнивания, что и приведет к отказу в обслуживании запущенной функции.
a'\s+b — в этом случае неверно выбран квантификатор. Знак + в регулярных выражениях означает «1 или более». Соответственно, мы можем передать «a'-пробел-0-раз-b», тем самым обойдя регулярку и выполнив вредоносную нагрузку.
a[\n]*b — здесь используется черный список. Всегда нужно помнить, что большинству Unicode-символов существуют эквивалентные альтернативы, которые могут быть не учтены в списке регулярки. Использовать блек-листы нужно с осторожностью. В данном случае обойти правило можно так: a\rb.

Особенности парсеров и опечатки
[A-z] — в этом примере разрешен слишком широкий скоуп. Кроме желаемых диапазонов символов A-Z и a-z, такое выражение разрешает еще и ряд спецсимволов, в числе которых \, `,[,] и так далее, что в большинстве случаев может привести к выходу за контекст.
[digit] — здесь отсутствует двоеточие до и после класса digit (POSIX character set). В данном случае это просто набор из четырех символов, все остальные разрешены.
a |b, a||b. В первом случае допущен лишний пробел — такое выражение будет искать не «a или b», а «а пробел, или b». Во втором случае подразумевался один оператор «или», а написано два. Такое выражение найдет все вхождения a и пустые строки (ведь после | идет пустая строка), но не b.
\11 \e \q — в этом случае конструкции с бэкслешами неоднозначны, так как в разных парсерах спецсимволы могут обрабатываться по-разному в зависимости от контекста. В разных парсерах спецсимволы могут обрабатываться по-разному. В этом примере \11 может быть как бэклинком с номером 11, так и символом табуляции (0x09 в восьмеричном коде); \e может интерпретироваться как очень редко описываемый в документации wildcard (символ Esc); \q — просто экранированный символ q. Казалось бы, один и тот же символ, но читается он по-разному в зависимости от условий и конкретного парсера.

https://github.com/attackercan/regexp-security-cheatsheet

```

Методология тестирования Web-приложения

```
1. Разведка
Сканирование портов
Отображение видимого контента
Поиск скрытого контента
Поиск параметров отладки и разработки
Определение точек ввода данных
Определение используемых технологий
Отображение возможных векторов атаки

2. Тестирование контроля доступа
Аутентификация:
        Определение правил стойкости пароля
        Тестирование подбора логина
        Тестирование подбора пароля
        Тестирование восстановления аккаунта
        Тестирование функции «Запомнить меня»
        Тестирование функции идентификации пользователя
        Проверка распределения полномочий
        Проверка уникальности логина
        Тестирование многоступенчатых механизмов
Управление сессиями:
        Проверка токенов на предсказуемость
        Проверка безопасности передачи токенов
        Проверка отображения токенов в логах
        Проверка многократного использования токенов
        Проверка завершения сеанса
        Проверка фиксации сессии
        Тестирование уязвимости CSRF
Контроль доступа:
        Определение требований контроля доступа
        Тестирование эффективности многопользовательского управления
        Тестирование незащищённого доступа к методам управления

3. Проверка входных данных
Фаззинг всех параметров
Тестирование SQL-инъекций
Тестирование XSS-уязвимостей
Тестирование инъекций в HTTP заголовках
Тестирование переадресаций
Тестирование инъекций команд ОС
Тестирование уязвимости Pah Traversal
Тестирование HTML/JavaScript-инъекций
Тестирование RFI и LFI
Тестирование SMTP-инъекций
Тестирование SOAP-инъекций
Тестирование LDAP-инъекций
Тестирование XPath-инъекций
Тестирование XXE-инъекций
Тестирование внедрения шаблона

4. Тестирование логики приложения
Определение векторов атаки
Тестирование передачи данных на стороне клиента
Тестирование валидации данных на стороне клиента
Тестирование компонентов толстых клиентов
Тестирование логики многоступенчатых механизмов
Тестирование обхода аутентификации
Тестирование прав доступа
Тестирование логики транзакций
Тестирование IDOR-уязвимостей

5. Изучение инфраструктуры приложения
Тестирование разделения в среде виртуального хостинга
Тестирование разделения между ASP-приложениями
Тестирование уязвимостей на сервере
Проверка стандартных учётных записей
Определение стандартного контента на сайте
Определение опасных HTTP-методов
Тестирование прокси

6. Прочие тесты
Тестирование DOM-модели
Тестирование frame-инъекций
Проверка локальных уязвимостей
Проверка параметров cookies
Определение конфиденциальных данных в URL-параметрах
Проверка наличия слабых SSL-шифров
Анализ HTTP-заголовков
```

Систематизированный подход
```
1. Разведка
Для начала нужно собрать как можно больше информации. Найти включенные службы, скрытые папки, возможные логины. 
Разведка делится на активную и пассивную.

Активная разведка – прямое взаимодействие с сервисом. Изучите исходный код сайта, в нём можно встретить забытые комментарии, обнаружить ссылки и скрипты. Найдите все активные элементы (например, кнопки). Определите все места ввода данных для построения возможных векторов атаки. Соберите почтовые ящики, имена сотрудников. Изучите файл robots.txt, используйте dirbuster для обнаружения доступных папок и файлов. Попробуйте найти режим отладки, параметры разработчика. При сканировании портов nmap’ом не ограничивайтесь стандартными, изучите все 65535 портов. Определите версии включенных сервисов, они могут оказаться уязвимыми.

При тестировании важен как активный, так и пассивный этап разведки. Соберите информацию о сайте с помощью всевозможных сторонних сервисов. Изучите github-аккаунты сотрудников, там можно найти исходные коды внутренних инструментов фирмы. В вакансиях компании можно узнать используемые технологии, версии СУБД и т.д. Используйте дорки для поиска файлов, доменов и прочего. Shodan поможет найти подключенные к интернету устройства. С помощью сервиса Wayback Machine можно найти забытые бекапы и прочее.

2. Тестирование контроля доступа
Аутентификация:
      Проверьте правила при создании пароля – длину пароля, разрешённые символы. Эти данные помогут нам при подборе паролей.     Протестируйте, есть ли ограничения на количество попыток ввода пароля.
      Аналогично протестируйте логин. Проверьте правила для него – возможно, вы сможете обнаружить XSS. В случае реализации       правил на стороне клиента – это можно легко обойти, отредактировав код сайта в браузере.
      Проверьте форму входа – если при некорректных данных возвращаются разные ответы, то есть возможность подобрать логины.     Также протестируйте функцию восстановления аккаунта.
      Проверьте функцию “Запомнить меня” – имеет ли она срок действия, уязвим ли соответствующий параметр.
      Протестируйте распределение полномочий, проверьте возможность начать какое-либо действие под одним логином,а    закончить с его подменой.

Управление сессиями:
      Проверьте безопасность токенов сессии. С ними можно обнаружить множество проблем. Попробуйте перехватить их,        предугадать значение, найти в логах. Проверьте многократность их использования. Протестируйте CSRF-уязвимость.(Это функция, достойная обеспечения? (CSRF, смешанный режим))

Контроль доступа:
      Определите разграничения доступа, проверьте контроль доступа для различных пользователей. Протестируйте доступ к методам управления.

3. Проверка входных данных
      Проведите фаззинг всех параметров. Попробуйте обнаружить SQL-инъекции, XSS-уязвимости, FPD, LFI и RFI, внедрение шаблона (Server Side и Client Side), прочие инъекции. (Кажется ли, что страница может вызвать хранимые данные? (Инъекции всего типа, ссылки на косвенные объекты, хранилище на стороне клиента). (Или может ли он) взаимодействовать с файловой системой сервера? (Fileupload vul, LFI и т. д.))

4. Тестирование логики приложения
      Определите главные цели в логике приложения. Попробуйте обнаружить передачу данных на стороне клиента, их валидацию (тогда вы сможете их корректировать). Изучите многоступенчатые механизмы, попробуйте пропустить один из этапов, например этап оплаты. Проверьте такие компоненты клиента, как Java, ActiveX, Flash. Протестируйте IDOR-уязвимости. (Функция является привилегированной? (логические недостатки, IDOR, приватные эскалации))
      Проверьте наличие мобильного приложения, изучите его на наличие утечек критичной информации.

5. Изучение инфраструктуры приложения
      Изучите всю среду виртуального хостинга, попробуйте обнаружить другой уязвимый сайт на этом же сервере. Протестируйте ASP-приложения.
      Проверьте стандартные учётные записи, администраторы часто забывают их удалить. Стандартный контент на сайте поможет определить его CMS, который может быть уязвим.
      Изучите все службы на открытых портах. Вы можете обнаружить уязвимый FTP, Proxy или SSH, найти панель управления почтовым клиентом.
      Изучите все HTTP-методы. Попробуйте их заменить, так вы сможете обойти фильтрацию.

6. Прочие тесты
      Исследуйте DOM-модель на наличие локальных XSS-уязвимостей. Проверьте стойкость SSL. Изучите HTTP-заголовки, параметры cookie.
      Используют ли они WAF, например CloudFront или CloudFlare? 
      Используют ли они CMS, такие как Wordpress, Drupal или Joomla? 
      Используют ли они фреймворк вроде AngularJS или CakePHP? 
      Какая версия Apache, nginx? 
      Используют ли они движок шаблонов, таких как Jinja2 или Smarty?
      Отображает ли функция страницы что-то для пользователей? (XSS, Spoofing для содержимого и т.д.) 
```

**Web Application Testing Methodologies**

```
RECON TOOLING

        Utilize port scanning
        -Don't look for just the normal 80,443 - run a port scan against all 65536 ports. You'll be surprised what can be running on random high ports. Common ones to look for re:Applications: 80,443,8080,8443,27201. There will be other things running on ports, for all of these I suggest ncat or netcat OR you can roll your own tools, always recommend that!
                Tools useful for this: nmap, masscan, unicornscan
                Read the manual pages for all tools, they serve as gold dust for answering questions.
        Map visible content
                Click about the application, look at all avenues for where things can be clicked on, entered, or sent.
                Tools to help: Firefox Developer Tools - Go to Information>Display links.
        Discover hidden & default content
                Utilize shodan for finding similar apps and endpoints - Highly recommended that you pay for an account, the benefits are tremendious and it's fairly inexpensive.
                Utilize the waybackmachine for finding forgotten endpoints
                Map out the application looking for hidden directories, or forgotten things like /backup/ etc.
                Tools: dirb - Also downloadable on most linux distrobutions, dirbuster-ng - command line implementation of dirbuster, wfuzz,SecLists.
        Test for debug parameters & Dev parameters
                RTFM - Read the manual for the application you are testing, does it have a dev mode? is there a DEBUG=TRUE flag that can be flipped to see more?
        Identify data entry points
                Look for where you can put data, is it an API? Is there a paywall or sign up ? Is it purely unauthenticated?
        Identify the technologies used
                Look for what the underlying tech is. useful tool for this is nmap again & for web apps specifically wappalyzer.
        Map the attack surface and application
                Look at the application from a bad guy perspective, what does it do? what is the most valuable part?
                        Some applications will value things more than others, for example a premium website might be more concerned about users being able to bypass the pay wall than they are of say cross-site scripting.
                        Look at the application logic too, how is business conducted?

ACCESS CONTROL TESTING
AUTHENTICATION
        The majority of this section is purely manual testing utilizing your common sense and eyes, does it look off? Should it be better? Point it out, tell your client if their password policy isn't up to scratch!

        Test password quality rules
                Look at how secure the site wants it's passwords to be, is there a minimum/maximum? is there any excluded characters - ',<, etc - this might suggest passwords aren't being hashed properly.
        Test for username enumeration
                Do you get a different error if a user exists or not? Worth noting the application behaviour if a user exists does the error change if they don't?
        Test resilience to password guessing
                Does the application lock out an account after x number of login attempts?
        Test password creation strength
                Is there a minimum creation length? Is the policy ridiculous e.g "must be between 4 and 8 characters passwords are not case sensitive" -- should kick off alarm bells for most people!
        Test any account recovery function
                Look at how an account can be recovered, are there methods in place to prevent an attacker changing the email without asking current user? Can the password be changed without knowing anything about the account? Can you recover to a different email address?
        Test any "remember me" function
                Does the remember me function ever expire? Is there room for exploit-ability in cookies combined with other attacks?
        Test any impersonation function
                Is it possible to pretend to be other users? Can session cookies be stolen and replayed? Does the application utilize anti-cross site request forgery?
        Test username uniqueness
                An you create a username or is it generated for you? Is it a number that can be incremented? Or is it something the user knows and isn't displayed on the application?
        Check for unsafe distribution of credentials
                How are logins processed, are they sent over http? Are details sent in a POST request or are they included in the URL(this is bad if they are, especially passwords)?
        Test for fail-open conditions
                Fail-open authentication is the situation when the user authentication fails but results in providing open access to authenticated and secure sections of the web application to the end user.
        Test any multi-stage mechanisms
                Does the application utilize multi-steps, e.g username -> click next -> password -> login, can this be bypassed by visiting complete page after username is entered?(similar to IDOR issues)
                Session Management
                How well are sessions handled, is there a randomness to the session cookie? Are sessions killed in a reasonable time or do they last forever? Does the app allow multiple logins from the same user(is this significant to the app?).
                Test tokens for meaning
                        - What do the cookies mean?!
        Test tokens for predictability
                Are tokens generated predictable or do they provide a sufficiently random value, tools to help with this are Burp Suite's sequencer tool.
        Check for insecure transmission of tokens
                This lies the same way as insecure transmission of credentials, are they sent over http? are they included in URL? Can they be accessed by JavaScript? Is this an Issue?
        Check for disclosure of tokens in logs
                Are tokens cached in browser logs? Are they cached server side? Can you view this? Can you pollute logs by setting custom tokens?
        Check mapping of tokens to sessions
                Is a token tied to a session, or can it be re-used across sessions?
        Check session termination
                is there a time-out?
        Check for session fixation
                Can an attacker hijack a user's session using the session token/cookie?
        Check for cross-site request forgery
                Can authenticated actions be performed within the context of the application from other websites?
        Check cookie scope
                Is the cookie scoped to the current domain or can it be stolen, what are the flags set> is it missing secure or http-only? This can be tested by trapping the request in burp and looking at the cookie.
        Understand the access control requirements
                How do you authenticate to the application, could there be any flaws here?
        Test effectiveness of controls, using multiple accounts if possible
        Test for insecure access control methods (request parameters, Referrer header, etc)

INPUT VALIDATION
        Fuzz all request parameters
                Look at what you're dealing with, are parameters reflected? Is there a chance of open redirection?
        Test for SQL injection
                Look at if a parameter is being handled as SQL, don't automate this off the bat as if you don't know what a statement is doing you could be doing DROP TABLES.
        Identify all reflected data
        Test for reflected cross site scripting (XSS)
        Test for HTTP header injection
        Test for arbitrary redirection
        Test for stored attacks
        Test for OS command injection
        Test for path traversal
        Test for JavaScript/HTML injection - similar to xss
        Test for file inclusion - both local and remote
        Test for SMTP injection
        Test for SOAP injection - can you inject SOAP envelopes, or get the application to respond to SOAP, this ties into XXE attacks too.
        Test for LDAP injection - not so common anymore but look for failure to sanitise input leading to possible information disclosure
        Test for XPath injection - can you inject xml that is reflected back or causes the application to respond in a weird way?
        Test for template injection - does the application utilize a templating language that can enable you to achieve xss or worse remote code execution?
        There is a tool for this, automated template injection with tplmap
        Test for XXE injection - does the application respond to external entity injection?

APPLICATION/BUSINESS LOGIC
        Identify the logic attack surface
                What does the application do, what is the most value, what would an attacker want to access?
        Test transmission of data via the client
                Is there a desktop application or mobile application, does the transferral of information vary between this and the web application 
        Test for reliance on client-side input validation
                Does the application attempt to base it's logic on the client side, for example do forms have a maximum length client side that can be edited with the browser that are simply accepted as true?     
        Test any thick-client components (Java, ActiveX, Flash)
                Does the application utilize something like Java, Flash, ActiveX or silverlight? can you download the applet and reverse engineer it?
        Test multi-stage processes for logic flaws
                Can you go from placing an order straight to delivery thus bypassing payment? or a similar process?
        Test handling of incomplete input
                Can you pass the application dodgy input and does it process it as normal, this can point to other issues such as RCE & XSS.
        Test trust boundaries
                What is a user trusted to do, can they access admin aspects of the app?
        Test transaction logic
        Can you pay £0.00 for an item that should be £1,000,000 etc?
        Test for Insecure direct object references(IDOR)
        Can you increment through items, users. uuids or other sensitive info?

SERVER/APPLICATION INFRASTRUCTURE
        Test segregation in shared infrastructures/ virtual hosting environments
        Test segregation between ASP-hosted applications
        Test for web server vulnerabilities - this can be tied into port scanning and infrastructure assessments
        Default credentials
        Default content
        Dangerous HTTP methods
        Proxy functionality
        
MISCELLANEOUS TESTS
        Check for DOM-based attacks - open redirection, cross site scripting, client side validation.
        Check for frame injection, frame busting(can still be an issue)
        Check for local privacy vulnerabilities
        Persistent cookies
        Weak cookie options
        Caching
        Sensitive data in URL parameters
        Follow up any information leakage
        Check for weak SSL ciphers
        HTTP Header analysis - look for lack of security headers such as:
                Content Security Policy (CSP)
                HTTP Strict Transport Security (HSTS)
                X-XSS-Protection
                X-Content-Type-Options
                HTTP Public Key Pinning
```

**Инструменты**

```
virtualenv -p python3 env
virtualenv venv

Wappalyzer *
https://chrome.google.com/webstore/detail/wappalyzer/gppongmhjkpfnbhagpmjfkannfbllamg?hl=ru

Validators, generators and converters *
https://mothereff.in/

Charref *
https://dev.w3.org/html5/html-author/charref

Knockpy *
https://github.com/guelfoweb/knock

Запуск
git clone https://github.com/guelfoweb/knock.git
cd knock
Set your virustotal API_KEY:
vim knockpy/config.json
sudo python setup.py install

knockpy domain.com -w wordlist.txt - Subdomain scan with external wordlist
knockpy -c domain.com - Save scan output in CSV

Arjun (find get post)
https://github.com/s0md3v/Arjun

THC-Hydra *
https://github.com/vanhauser-thc/thc-hydra

Striker - vulnerability scanner
https://github.com/s0md3v/Striker

Запуск
git clone https://github.com/UltimateHackers/Striker
cd Striker
pip install -r requirements.txt
python striker.py

XSStrike *
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
pip install -r requirements.txt
python3 xsstrike.py

Xsser
https://github.com/epsylon/xsser

Запуск
git clone https://github.com/epsylon/xsser
cd xsser
python setup.py install
./xsser -h
./xsser --gtk (for gui)

Xssor *
http://xssor.io/

Xsscrapy
git clone https://github.com/DanMcInerney/xsscrapy
cd xsscrapy
pip install -r requirements.txt
./xsscrapy.py -u http://target.com

Photon - vulnerability scanner
https://github.com/s0md3v/Photon

Запуск
git clone https://github.com/s0md3v/photon.git
cd Photon
python3 -m pip install -r requirements.txt
python3 photon.py -u "https://www.target.com/" -l 1 -t 10 -o results --dns

wapiti3 - vulnerability scanner
http://wapiti.sourceforge.net/
http://wapiti.sourceforge.net/wapiti.1.html
pip install wapiti3

Запуск
wapiti -u https://target/

Dig *
https://toolbox.googleapps.com/apps/dig/ (CNAME)

SqlMap *
http://sqlmap.org/
https://github.com/sqlmapproject/sqlmap

Запуск
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

cd sqlmap-dev/
python sqlmap.py -h

w3af *
http://docs.w3af.org/en/latest/install.html#installing-using-docker

Запуск через докер
git clone https://github.com/andresriancho/w3af.git
cd w3af/extras/docker/scripts/
sudo ./w3af_console_docker

recon-ng
https://github.com/lanmaster53/recon-ng.git

Запуск
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip install -r REQUIREMENTS
./recon-ng

Sublist3r (Subdomain) *
https://github.com/aboul3la/Sublist3r

Запуск
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
sudo pip install -r requirements.txt
python sublist3r.py -d target.com

Subbrute (Subdomain)
git clone https://github.com/TheRook/subbrute
cd subbrute

Запуск
./subbrute.py google.com

Subfinder
https://github.com/subfinder/subfinder

Запуск
go get -u github.com/subfinder/subfinder
./subfinder -d target.com -o output.txt

Censys-subdomain-finder
https://github.com/christophetd/censys-subdomain-finder

Запуск
git clone https://github.com/christophetd/censys-subdomain-finder.git
cd censys-subdomain-finder
pip install -r requirements.txt
python censys_subdomain_finder.py example.com

Gobuster
https://github.com/OJ/gobuster

Запуск
go get github.com/OJ/gobuster

Subdomain-takeover (list)
git clone https://github.com/antichown/subdomain-takeover

Запуск
python takeover.py -d target.com -w sublist.txt -t 20
-d => domain 
-w => wordlist 
-t => thread 

Nikto
https://github.com/sullo/nikto.git

Запуск
git clone https://github.com/sullo/nikto.git
cd nikto
docker build -t sullo/nikto .
# Call it without arguments to display the full help
docker run --rm sullo/nikto
# Basic usage
docker run --rm sullo/nikto -h http://www.example.com
# To save the report in a specific format, mount /tmp as a volume:
docker run --rm -v $(pwd):/tmp sullo/nikto -h http://www.example.com -o /tmp/out.json

aircrack wifi
https://www.aircrack-ng.org/

metasploit
https://www.metasploit.com/
http://www.exploit-db.com
https://www.cvedetails.com/

nmap *
brew install nmap
sudo apt install nmap

nmap --help
nmap --top-ports 1000 -T4 -sC https://target.com

wireshark
https://www.wireshark.org/

Maltego
https://www.paterva.com/downloads.php

ZAP (OWASP) *
https://github.com/zaproxy/zaproxy/wiki/Downloads
https://github.com/zaproxy/zaproxy/wiki/Docker

dirsearch *
https://github.com/Bo0oM/dirsearch.git

Запуск
python3 dirsearch.py -h
./dirsearch.py -u target.com -e *

Gobuster
https://github.com/OJ/gobuster

fuzz.txt
https://github.com/Bo0oM/fuzz.txt

Shodan
https://www.shodan.io/

Censys
https://censys.io/

```

```
Deploying a private Burp Collaborator server
https://portswigger.net/burp/documentation/collaborator/deploying

Awesome-burp-extensions
https://github.com/snoopysecurity/awesome-burp-extensions

OWASP Cheat Sheet Series
https://cheatsheetseries.owasp.org

Google Hacking
https://www.exploit-db.com/google-hacking-database
```
