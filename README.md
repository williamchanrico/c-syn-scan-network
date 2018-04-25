# c-syn-scan-network
C program to scan if some ports are open by sending SYN packets to all IP(s) in a network

## Usage
Need root permission
```
$ make
# ./syn-scan-network
usage: ./syn-scan-network <IP/CIDR> <Port1,Port2,...>
example:
	./syn-scan-network 166.104.0.0/16 80,443,8080
	./syn-scan-network 35.186.153.3 80,443,8080
	./syn-scan-network 166.104.177.24 80
```

## Example
Target single IP: [ 166.104.177.24 ]
```
$ sudo ./syn-scan-network 166.104.177.24 80,8080
Local IP: 192.168.200.169

SYN scan IP range for port(s) [80,8080]
From    : 166.104.177.24
To      : 166.104.177.24
1 host(s)

166.104.177.24	www.hanyang.ac.kr

Total active host: 1
Scan duration    : 0 hour(s) 0 min(s) 0.01036 sec(s)


$ sudo ./syn-scan-network 35.186.153.3 80,443,8080
Local IP: 192.168.200.169

SYN scan IP range for port(s) [80,443,8080]
From    : 35.186.153.3
To      : 35.186.153.3
1 host(s)

35.186.153.3	arzhon.id

Total active host: 1
Scan duration    : 0 hour(s) 0 min(s) 0.09302 sec(s)
```
Target a subnet (CIDR notation): [ 166.104.177.24/16 ]
```
$ sudo ./syn-scan-network 166.104.0.0/16 80,8080
Local IP: 192.168.200.169

SYN scan IP range for port(s) [80,8080]
From    : 166.104.0.1
To      : 166.104.255.254
65536 host(s)

[DEBUG] Sending SYN packet to 166.104.0.1:80
[DEBUG] Sending SYN packet to 166.104.0.1:8080
[DEBUG] Sending SYN packet to 166.104.0.2:80
[DEBUG] Sending SYN packet to 166.104.0.2:8080
[DEBUG] Sending SYN packet to 166.104.0.3:80
[DEBUG] Sending SYN packet to 166.104.0.3:8080
[DEBUG] Sending SYN packet to 166.104.0.4:80
^C
.
.
[Not tested yet]
```

## Preview
![Screenshot](screenshot01.png?raw=true "Screenshot")

## Used Compiler
```
$ gcc --version
gcc (GCC) 7.3.1 20180312
Copyright (C) 2017 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```
