#define MSG1 "The traced application attempts to open a file for WRITING. This may be a\n \
legitimate operation, or an attempt to backdoor or corrupt the system (by\n \
modifying files such as /etc/passwd, binaries, .ssh/authorized_keys, etc).\n \
Because of the risk, you should examine the filename and use caution.\n\n"
              
#define MSG2 "The traced application attempts to CREATE a new file. This may be a\n \
legitimate operation, but creation of certain system files can also be an\n \
attempt to backdoor the system (.ssh/authorized_keys, /etc/ld.so.preload,\n \
etc). Because of the risk, you should examine the filename and use caution.\n\n"
 	          
#define MSG3 "The traced application attempts to open a file for WRITING. Remote exploits\n \
seldom should. This may be an attempt to backdoor or corrupt the system (by\n \
modifying files such as /etc/passwd, binaries, .ssh/authorized_keys, etc).\n \
Because of the risk, you should examine the filename and use caution.\n\n"
 	          
#define MSG4 "The traced application attempts to CREATE a new file. Remote exploits seldom\n \
need to do this. Creation of certain system files may indicate an attempt to\n \
backdoor the system (.ssh/authorized_keys, /etc/ld.so.preload, etc).\n \
Because of the risk, you should examine the filename and use caution.\n\n"
 	          
#define MSG5 "The traced application attempts to open a file for READING. This will do no\n \
harm, but if the file contains sensitive information, and the exploit has no\n \
business accessing the data, there is a risk of privacy exposure.\n\n" 	          
              
#define MSG6 "The traced application attempts to issue a rare I/O CONTROL COMMAND (ioctl)\n \
on a file descriptor. Certain ioctls may manipulate devices, network settings,\n \
or simply alter the look or functionality of the terminal you are using to\n \
spoof your input to this debugger.\n\n"              
              
#define MSG7 "The traced application attempts to create a %sLINK. Some local exploits\n \
use such links as a real exploitation vector, but it is advised to examine\n \
which file is being linked, and for what reason.\n\n"              
  	          
#define MSG8 "The traced application attempts to create a %sLINK. Remote exploits\n \
have no reason to create such links. You are strongly advised to examine\n \
which file is being linked, and for what reason.\n\n"
	          
#define MSG9 "The traced application attempts to DELETE a file. Although this by itself\n \
is seldom a problem, you are advised to check if this is not an important\n \
system file, or something else deleted against your will.\n\n"
              
#define MSG10 "The traced application attempts to EXECUTE a new program and terminate self.\n \
This concludes the analysis of this application. Below is the summary of\n \
the execution attempt for you to determine its legitimacy:\n\n"              

#define MSG11 "The traced application attempts to EXECUTE a new program and terminate self.\n \
For a remote exploit, this often indicates malicious behavior. Either way,\n \
this concludes the analysis of this application. Below is the summary of\n \
the execution attempt for you to determine its legitimacy:\n\n"

#define MSG12 "The traced application attempts to create a SPECIAL DEVICE as root. There is\n \
no legitimate explanation such activity. If allowed, this action may\n \
effectively backdoor the system.\n\n"

#define MSG13 "The traced application attempts to make a file SETUID. There is no legitimate\n \
explanation for such activity. If the target is a system file, this action may\n \
effectively backdoor the machine.\n\n"
  
#define MSG14 "The traced application attempts to make a file WORLD WRITABLE. There is usually\n \
no reason for an exploit to do this. If the target is a system file, this\n \
action may effectively backdoor the machine.\n\n"  

#define MSG15 "The traced application attempts to CHANGE PERMISSIONS on a file. Local\n \
exploits sometimes do this, but you are advised to check if this is not\n \
an important system file.\n\n"

#define MSG16 "The traced application attempts to CHANGE PERMISSIONS on a file. Remote\n \
exploits have no reason to do this. You are advised to check if this is not\n \
an important system file.\n\n"

#define MSG17 "The traced application attempts to CHANGE OWNER of a file as root. There is\n \
no legitimate explanation such activity. If allowed, this action may\n \
effectively backdoor the system.\n\n"

#define MSG18 "The traced application attempts to MOUNT A FILESYSTEM as root. There is\n \
no legitimate explanation such activity. If allowed, this action may\n \
have adverse effects on the system, or help hide backdoors.\n\n"

#define MSG19 "The traced application attempts to UNMOUNT A FILESYSTEM as root. There is\n \
no legitimate explanation such activity. If allowed, this action may have\n \
adverse effects on the system.\n\n"

#define MSG20 "The traced application attempts to CHANGE SYSTEM TIME as root. There is\n \
no legitimate explanation such activity. If allowed, this action may have\n \
adverse effects on the system.\n\n"

#define MSG21 "The traced application attempts to ATTACH TO A PROCESS AND DEBUG IT. Usually,\n \
exploits have no legitimate reason to do this. If a system process is tapped\n \
this way, the system may be easily backdoored.\n\n"

#define MSG22 "The traced application attempts to ALTER FILE ACCESS TIMES. Some local exploits\n \
may have a legitimate reason to do this, but the action may also indicate an\n \
attempt to cover tracks of tampering with system files.\n\n"

#define MSG23 "The traced application attempts to ALTER FILE ACCESS TIMES. There is usually\n \
no legitimate explanation such activity. The action may be indicative of\n \
an attempt to cover tracks of tampering with system files.\n\n"

#define MSG24 "The traced application attempts to KILL A PROCESS. In general, exploits have\n \
no reason to do this. If a system process is killed, certain services may be\n \
denied.\n\n"

#define MSG25 "The traced application attempts to RENAME A FILE. Some local exploits may\n \
conceivably shuffle files around, but it is advised to examine which file\n \
is being renamed, and for what reason.\n\n"
             
#define MSG26 "The traced application attempts to RENAME A FILE. Remote exploits have no\n \
reason to shuffle files around. You are strongly advised to examine which\n \
file is being renamed, and for what reason.\n\n"             
           
#define MSG27 "The traced application attempts to CREATE A WORLD-WRITABLE DIRECTORY. Local\n \
exploits may have a reason to do this, but there is a risk in having such\n \
directories. You are advised to verify the operation and its purpose.\n\n"
       
#define MSG28 "The traced application attempts to CREATE A DIRECTORY. Local exploits may\n \
have a reason to do this, and the risk involved is fairly low, but you are\n \
advised to verify the operation and its purpose.\n\n"
            
#define MSG29 "The traced application attempts to CREATE A DIRECTORY. Remote exploits have\n \
no legitimate reason to try this. You are strongly advised to examine what\n \
is happening, and why.\n\n"            

#define MSG30 "The traced application attempts to DELETE AN EMPTY DIRECTORY. Local exploits\n \
may have a reason to do this, and the risk involved is fairly low, but you are\n \
advised to verify the operation and its purpose.\n\n"

#define MSG31 "The traced application attempts to DELETE AN EMPTY DIRECTORY. Remote exploits\n \
have no business doing this. You are advised to examine what is happening, and\n \
why. There is no significant risk associated with this action, though.\n\n"
           
#define MSG32 "The traced application attempts to RECONFIGURE PROCESS ACCOUNTING as root.\n \
Legitimate exploits have no business doing it.\n\n \
		       Log file : %s\n\n"           

#define MSG33 "The traced application attempts to DISABLE PROCESS ACCOUNTING as root.\n \
Legitimate exploits have no business doing it.\n\n"

#define MSG34 "The traced application attempts to PIVOT / DIRECTORY as root. Legitimate\n \
exploits have no business doing it. Such an action may be aimed at confusing\n \
debuggers. You are advised to 'sink' it.\n\n \
               New root : %s\n\n"

#define MSG35 "The traced application attempts to CHANGE HOST OR DOMAIN as root. Legitimate\n \
exploits have no business doing it. Such an action may affect the system.\n \
You are advised to 'sink' it.\n\n \
                New name : %s\n\n"

#define MSG36 "The traced application attempts to CREATE NEW SWAP SPACE as root. Legitimate\n \
exploits have no business doing it. Such an action may be aimed at gaining\n \
access to system memory.\n\n \
                Swapfile : %s\n\n"

#define MSG37 "The traced application attempts to REBOOT MACHINE as root. Legitimate\n \
exploits usually do not try to commit suicide. Such an action may have adverse\n \
effect on the availability of services, of course.\n\n"
           
#define MSG38 "The traced application attempts to ACCESS I/O PORTS as root. Legitimate\n \
exploits have no reason to try this. Such an action enables the process to\n \
directly tamper with hardware, including hard disks and various chips.\n\n"
           
#define MSG39 "The traced application attempts to OBTAIN RAW SOCKET. Such a socket can\n \
be used to send and receive arbitrary data, possibly without supervision.\n \
Local exploits have no reason to request raw socket access.\n\n"

#define MSG40 "The traced application attempts to OBTAIN RAW SOCKET. Such a socket can\n \
be used to send and receive arbitrary data, possibly without supervision.\n \
Very few remote exploits have a reason to request raw socket access.\n\n"

#define MSG41 "The traced application attempts to OBTAIN RIGHTS TO USE UNIDENTIFIED\n \
PROTOCOL over the network. Such a protocol will be likely impossible to fully\n \
supervise, and may be used to leak data to the outside world.\n\n"

#define MSG42 "The traced application attempts to CREATE A UNIX SOCKET. Local exploits may\n \
have a reason to do this, and the risk involved is fairly low, but you are\n \
advised to verify the operation and its purpose.\n\n"

#define MSG43 "The traced application attempts to CREATE A UNIX SOCKET. Remote exploits have\n \
no reason to do this. Although the risk is low, such sockets may interfere\n \
certain OS processes.\n\n"

#define MSG44 "The traced application attempts to CONNECT TO A UNIX SOCKET. Local exploits \
may have a reason to do this. Such a socket may be used to send data to a\n \
rogue local application, or to attack third-party software, hence you are\n \
still advised to verify the operation and its purpose.\n\n"

#define MSG45 "The traced application attempts to CONNECT TO A UNIX SOCKET. Remote exploits\n \
seldom have a reason to try. Such a socket may be used to send data to a\n \
rogue local application, or to attack third-party software, hence you are\n \
advised to verify the operation and its purpose.\n\n"

#define MSG46 "The traced application attempts to CONNECT TO A HOST. Local exploits\n \
usually have no reason to do this. Such a connection may be used to send\n \
sensitive information to a remote system, or to accept attacker's comands.\n \
Do verify the destination address and the purpose of this connection.\n\n"

#define MSG47 "The traced application attempts to CONNECT TO A HOST. Remote exploits\n \
often do connect to their target, but such a connection may be used to send\n \
sensitive information to a remote system, or to accept attacker's comands.\n \
Be sure to compare the target IP with the displayed destination below.\n\n"

#define MSG48 "The traced application attempts to CONNECT TO A HOST. Local exploits\n \
usually have no reason to do this. Such a connection may be used to send\n \
sensitive information to a remote system, or to accept attacker's comands.\n \
Do verify the destination address and the purpose of this connection.\n\n"

#define MSG49 "The traced application attempts to CONNECT TO A HOST. Remote exploits\n \
often do connect to their target, but such a connection may be used to send\n \
sensitive information to a remote system, or to accept attacker's comands.\n \
Be sure to compare the target IP with the displayed destination below.\n\n"

#define MSG50 "The traced application attempts to CONNECT TO A HOST using an unidentified\n \
network protocol. Exploits seldom have a reason to use protocols other than\n \
unix sockets and IP to establish a connection. Although the destination host\n \
cannot be determined, there is a reason to suspect trickery. Such a connection\n \
could be used to send sensitive data to a remote host.\n\n \
		       Address family ID : 0x%x\n\n"

#define MSG51 "The traced application attempts to SEND DATA TO A HOST. Local exploits usually\n \
have no reason to send data over the network. You are advised to examine all\n \
details of this operation to avoid information leakage.\n\n"

#define MSG52 "The traced application attempts to SEND DATA TO A HOST using an unknown ADDRESS\n \
SCHEME. Although remote exploits may have a reason to do this, determining the\n \
target may be problematic, and hence you are advised to exercise caution.\n\n"

#define MSG53 "The traced application attempts to SEND DATA TO A HOST. Please examine the\n \
data below to make sure the connection is legitimate and solicited.\n\n"

#define MSG54 "The traced application attempts to ACCESS KERNEL LOG BUFFER as root. Legitimate\n \
exploits seldom have a reason to try this. Such an action may disclose some\n \
marginally sensitive information, or hide evidence of tampering.\n\n"

#define MSG55 "The traced application attempts to ACCESS I/O PORTS as root. Legitimate\n \
exploits have no reason to try this. Such an action enables the process to\n \
directly tamper with hardware, including hard disks and various chips.\n\n"

#define MSG56 "The traced application attempts to HANGUP TERMINAL as root. Legitimate\n \
exploits usually do not try to commit suicide. Such an action may affect\n \
the current debugger session.\n\n"

#define MSG57 "The traced application attempts to tamper with per-process CPU settings.\n \
Exploits have no reason to attempt this, although it is not clear what the\n \
program has to gain by trying this.\n\n"

#define MSG58 "The traced application attempts to DISABLE SWAP SPACE as root. Legitimate\n \
exploits have no business doing it. Such an action may affect system\n \
operations if physical memory is low.\n\n"

#define MSG59 "The traced application attempts to SEND DATA over IPC to another process.\n \
In most cases, exploits have no reason to do this. If the (local) recipient\n \
is controlled by an attacker, sensitive data may be exposed to him.\n\n"

#define MSG60 "The traced application attempts to RECEIVE DATA over IPC to another process.\n \
In most cases, exploits have no reason to do this. If the (local) sender\n \
put any sensitive data in the queue, it may be exposed to the program\n\n"

#define MSG61 "The traced application attempts to ATTACH TO SHARED MEMORY of another process.\n \
In most cases, exploits have no reason to do this. If the memory contains\n \
any sensitive data, it may be read or tampered with. This is also a potential\n \
attack vector against the owner.\n\n"

#define MSG62 "The traced application attempts to issue an UNKNOWN IPC operation. It is\n \
impossible to determine its purpose and effects, although there is likely no\n \
justification for this action.\n\n \
		       Operation : %d\n \
		       Resource  : %d\n\n"

#define MSG63 "The traced application attempts to fine-tune KERNEL CLOCK. It is unclear\n \
what there is to gain, but there is no justification for this operation.\n\n \
                Tweak mode: %d\n\n"
           
#define MSG64 "The traced application attempts to CREATE / INIT A KERNEL MODULE as root.\n \
There is no legitimate reason for an exploit to perform such an action.\n \
This operation may backdoor the system or render it unstable.\n\n \
                Module name: %s\n\n"
           
#define MSG65 "The traced application attempts to DELETE A KERNEL MODULE as root.\n \
There is no legitimate reason for an exploit to perform such an action.\n \
This operation may impair system functionality.\n\n \
                Module name: %s\n\n"           
           
#define MSG66 "The traced application attempts to ALTER SYSTEM PARAMETERS. There is no\n \
legitimate reason for an exploit to perform such an action. The operation may\n \
affect system functionality.\n\n"

#define MSG67 "The traced application attempts to CHANGE SCHEDULING POLICY for it or some\n \
other process to run in near realtime. Such an action may render the system\n \
nonresponsive or unstable.\n\n"

#define MSG68 "The traced application attempts to CHANGE PRIORITY of another process on the\n \
machine. There is no legitimate reason for it to tweak settings of other\n \
running tasks.\n\n"

#define MSG69 "The traced application attempts to modify EXTENDED ATTRIBUTES of files as root.\n \
There is no legitimate explanation for this activity; the program may be\n \
attempting to protect self or remove protection from other files.\n\n \
    	       File name : %s\n\n"

#define MSG70 "The traced application attempts to spawn a NEW PROCESS. This may be an\n \
attempt to invoke an external program, or to confuse debuggers. The exploit\n \
will be not permitted to carry out this action, but you may choose to continue\n \
tracing behavior of either parent or child, and terminate the other.\n\n"

#define MSG71 "The traced application attempts to spawn a NEW PROCESS. Legitimate remote\n \
exploits seldom have a reason to do this. This may be an attempt to execute\n \
an external command, or confuse debuggers. You may choose to continue\n \
tracing behavior of either parent or child, and terminate the other.\n\n"

#define MSG72 "The traced application attempts to CLONE OWN PROCESS. Legitimate exploits\n \
seldom have a reason to do this. Because of the deficiencies of Linux\n \
debugging facilities, the program will be terminated, and you will need to\n \
determine the purpose and functionality of the code manually.\033[0m\n"

#define MSG73 "The traced application attempts to execute an UNKNOWN SYSCALL. This may be\n \
an attempt to use a kernel feature unknown to this debugger. You are advised\n \
to locate documentation for this syscall, and determine whether there is a\n \
legitimate reason for the exploit to use it.\n\n"
           
#define MSG74 "The traced application attempts to execute an UNKNOWN SYSCALL. There is no\n \
reason for a legitimate remote exploit to attempt this. You are advised to\n \
abort the program until a viable explanation for the use of this feature can\n \
be found.\n\n"
           
#define MSG75 "The traced application attempts to ACCEPT A CONNECTION from the outside world.\n \
In most cases, there is no legitimate explanation for this. Such a connection\n \
may be used to send sensitive data back to the attacker. You are advised to\n \
proceed with caution.\n\n \
            Descriptor : %d\n \
            Endpoints  : %s\n\n"

#define MSG76 "The traced application attempts to RECEIVE DATA FROM A HOST. Local exploits\n \
have no reason to try this. You are advised to examine all the details of\n \
this operation.\n\n"

#define MSG77 "The traced application attempts to RECEIVE DATA FROM A HOST. Please examine\n \
the data below to make sure the transaction is legitimate.\n\n"

#define ABUSE_TRACEME "The traced application attempts to execute the ptrace syscall with option \n\
PTRACE_TRACEME. This option allow the process to be traced by your parent \n\
process. The ptrace syscall and PTRACE_TRACEME request generally are executed\n\
by debuggers immediately after a fork, to enable debug the child process. \n\
Executing ptrace with PTRACE_TRACEME can also be used by **MALWARES** to find\n\
out if they are being debugged, this trick allow them to fool debuggers and exit\n\
the malicious program silently.\n\n"
