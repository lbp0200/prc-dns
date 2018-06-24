- Install Python
- Install pip
- Install prc-dns

Run prc-dns as Service

Install Unbound

Unbound Config File

```
server:
	# verbosity level 0-4 of logging
	verbosity: 0

	# if you want to log to a file use
	#logfile: "C:\unbound.log"

	# on Windows, this setting makes reports go into the Application log
	# found in ControlPanels - System tasks - Logs 
	use-syslog: no
	do-ip6: no
	do-tcp: no
	do-udp: yes
	tcp-upstream: yes

forward-zone:
	name: "prc-dns"
	forward-addr: 127.0.0.2@5333
```