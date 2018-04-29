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
```
$ sudo ./syn-scan-network 166.104.96.13/30 80,8080
SYN scan [166.104.96.13/30]:[80,8080]
4 host(s): 166.104.96.13 -> 166.104.96.14

166.104.96.13	hmcgw.hanyang.ac.kr
166.104.96.14	hmcmail.hanyang.ac.kr

Total active host: 2
Scan duration    : 0 hour(s) 0 min(s) 2.42778 sec(s)


$ sudo ./syn-scan-network 35.186.153.3 80,443,8080
SYN scan [35.186.153.3]:[80,443,8080]
1 host(s): 35.186.153.3 -> 35.186.153.3

35.186.153.3	arzhon.id

Total active host: 1
Scan duration    : 0 hour(s) 0 min(s) 0.10277 sec(s)
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
