# ***DEPRECATED*** PowerScan

		                  PowerScan - Version 0.9.3b Beta                  
	  _____________________________________________________________________________   
	 |                  |                    |                  |                  |  
	 |     IP Range     |       Ports        |     Progress     |   Open Servers   |  
	 |-----------------------------------------------------------------------------|  
	 |                  |                    |                  |                  |  
	 |   10.10.0.0/16   |       22,123       |   11 %  [7424]   |    83  [167]     |  
	 |__________________|____________________|__________________|__________________| 

	Usage: # powerscan [required] [optional]

	Options:
	  -h, --help          show this help message and exit
	  -v, --version       display the the version of powerscan

	  Required:
		-i range          set IP range [10.0.0.0/24]
		-l file           load IPs from file [1 IP/line]
		-p ports          specify ports seperated by ',' or '-' for range

	  Optional:
		--threads=1-64    number of threads
		--processes=1-32  number of processes [default=cpu_count]
		--timeout=2       set timeout [1-5]
		--noping          do not ping targets
		--hostname        discover hostnames for open servers
		--os              discover os for open servers [slow]
		--service         discover services for open ports
		--brute           only save servers that are vuln againt brute-forcing
		--amp             only save servers with amplification factor
		--verbose         run in verbose mode
		--out=file        set output file

	  Examples:
		# powerscan -i 10.10.10.0/24 -p 21,22,53,123
		# powerscan -i 10.10.0.0/16 -p 22 --threads=16 --processes=4 --hostname
		# powerscan -l hosts.txt -p 22 --noping --service --brute --verbose

<b>Time Results:</b>

	[CPU: octa core | Network: 1Mbps Upstream]

	# powerscan -i 10.10.0.0/* -p 80 --threads=64 --processes=32 --timeout=0.5 --noping
	 _______________________________________________
	|-----SUBNET-----|----TIME----|------IP'S-------|
	|   /32 subnet   |    <1sec   |   1 ip          |
	|   /24 subnet   |    ~1sec   |   256 ips       |
	|   /16 subnet   |    ~8sec   |   65536 ips     |
	|   /8  subnet   |    ~35min  |   16777216 ips  |
	 ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾

<b>Installation:</b>

	# git clone "https://github.com/vP3nguin/powerscan.git"
	# cd powerscan
	# sudo python setup.py build
	# sudo python setup.py install
	# sudo powerscan -h
	
<b>Dependencies:</b>

	python version 2.7   - https://www.python.org/downloads/
	module scapy         - https://github.com/secdev/scapy.git
	module netaddr       - https://github.com/drkjam/netaddr.git
	module numpy         - https://github.com/numpy/numpy.git
	module paramiko      - https://github.com/paramiko/paramiko.git
	module python-nmap   - https://bitbucket.org/xael/python-nmap
	SYSTEM_PATH          - /dev/null

	**you can also use pip to install most dependencies

<b>In Progress:</b>

	- add more protocols for brute-force/amplification detection
	  currently supported brute-forcing: ssh
	  currently supported amplification: dns,ntp,snmp,ssdp,chargen,quake 
	- add more possibilities for output
	  currently supported output: file
	- implement usage handler for cpu and network upstream

<b>Known Bugs and Issues:</b>

	- pressing CTRL+C when os discovery is running throws a keyboard exception
	- trouble if we use more network speed as we have


