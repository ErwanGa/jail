# Jail
## 1. Overview
This program will launch and monitor a jailed process

## 2. Build
> make


## 3. Install


## 4. Usage
``` bash
jail data.xml
```
where data.xml has the following scheme
```xml
<jail name="/bin/ls">
	<user username="myUser"/>
	<rlimit as="0" fsize="0" mq="0" stack="0" />
	<umask value="0077"/>
	<home path="myHome" />
	<bind_ro path="/bin /lib /usr/lib" />
	<bind_rw path="/mnt" />
	<copy_d path="" />
	<copy_f path="/etc/group /etc/passwd /etc/apt/apt.conf" />
	<caps name="" />
	<args name="-l"/>
	<restart value=y>
	<reboot value=y>

</jail>
```
jail name is the name of the process (absolute path)
user username is the owner of the process
rlimit fix the system limits (0 means unlimited)
bind\_ro is a list of directory to bind in read only mode
bind\_rw is a list of directories to bind in read-write mode if possible
copy\_d is not used yet
copy\_f is a list a file to be copied in the jail
caps is a list a capabilities
args is a list of argumet for the program
restart value (y|n) y -\> restart if the process ends
reboot value (y|n) y -\> reboot if the process ends

