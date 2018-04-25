# c-syn-scan-network
C program to scan if a port if open by sending SYN packet to all IP(s) in a network

## Usage
Need root permission
```
$ make
# ./syn-scan-network
usage: ./syn-scan-network <IP/CIDR> <Port>
example:
	./syn-scan-network 166.104.0.0/16 80
	./syn-scan-network 166.104.177.24/16 80
	./syn-scan-network 166.104.177.24 80
```

## Example
Target single IP: [166.104.177.24]
```
$ sudo ./syn-scan-network 166.104.177.24 80
Current local source IP is 192.168.200.169

From:	 166.104.177.24
To:	 166.104.177.24
1 host(s) as targets

166.104.177.24	www.hanyang.ac.kr

Total open host: 1
```
Target subnet (CIDR notation): [166.104.177.24/16]
```
$ sudo ./syn-scan-network 166.104.177.24/16 80
Current local source IP is 192.168.200.169

From:	 166.104.0.1
To:	 166.104.255.254
65536 host(s) as targets

.
.
[Not tested yet, takes a long time]
```

## Used Compiler
```
$ gcc --version
gcc (GCC) 7.3.1 20180312
Copyright (C) 2017 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```
