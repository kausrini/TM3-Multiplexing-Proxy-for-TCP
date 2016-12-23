# TM3-Multiplexing-Proxy-for-TCP
Implement the Remote Proxy for the TM3 System

This project Implements the Remote Proxy for TM3 Multiplexing Proxy.

TM3 Multiplexing Proxy is based on the research paper - Feng Qian, Vijay Gopalakrishnan, Emir Halepovic, Subhabrata Sen, and Oliver Spatscheck, "TM3: Flexible Transport-layer Multi-pipe Multiplexing Middlebox Without Head-of-line Blocking", ACM CoNEXT 2015, Heidelberg, Germany, DOI: http://dx.doi.org/10.1145/2716281.2836088.

1. Set Up the Working Environment

You need to set up a dedicated Ubuntu virtual machine (VM) to run the LP, and a dedicated cloud
server to host the RP, by following the instructions below. You must use 64-bit Ubuntu 14.04 for
both LP and RP (installation image provided below), because my model implementations do not
run on other Linux distributions.
LP Setup. Download the Ubuntu image from here: http://www.cs.indiana.edu/~fengqian/
ubuntu-14.04.3-desktop-amd64.iso. Use a virtual machine software (e.g., VMware or VirtualBox) to create the VM.
Log onto the VM and type the following commands (you need Internet connectivity):
sudo apt-get update
sudo apt-get install g++
If you are using VirtualBox and find the screen size is too small, do the following:
sudo apt-get install virtualbox-guest-dkms
sudo apt-get remove libcheese-gtk23
sudo apt-get install xserver-xorg-core
sudo apt-get install -f virtualbox-guest-x11
Reboot the VM, and then do
sudo apt-get install ubuntu-desktop
You do not need to install other updates prompted by Ubuntu. Also, follow the link to enable a shared folder between your guest Ubuntu and your host OS: http://helpdeskgeek.com/
virtualization/virtualbox-share-folder-host-guest/.
(Note the above instructions are specifically for VirtualBox.)
RP Setup. Create an Amazon EC2 instance of Ubuntu Server 14.04 LTS. Make sure you use a
\free tier" instance that gives you one-year free trial. Open TCP port 6000 that will be used by
the pipes.
Log onto the server using the following command on any Linux terminal:
ssh -i key.pem ubuntu@52.23.220.80
where key.pem is the key pair name you downloaded when creating the EC2 instance. The default
user name is ubuntu. 52.23.220.80 is the server’s public IP address. Then type the following
commands:
sudo apt-get update
sudo apt-get install g++

2. Run the Model Implementation

We first copy the model implementation to LP and RP.
1. Copy remote proxy to RP. This is the RP program.
2. Copy local proxy to LP. This is the LP program.
3. Copy tm3.c, Makefile, and tm3 mod.pl to LP. Type make under the same directory. It will
generate a file called tm3.ko. This is a Linux kernel module that transparently forwards traffic to
LP.
Now let’s conduct two experiments. Assume the RP’s public IP address is 52.23.220.80. The first
experiment is illustrated in Figure 4 where we download data from our home-made server using
TM3.
1. Copy server.cpp to the RP host. Build it by g++ ./server.cpp -o ./server. This is the
server program. Start it by ./server 6001 10 (port 6001 needs to be opened using the EC2
management interface).
2. Copy client.cpp to the LP host. Build it by g++ ./client.cpp -o ./client. This is the
client program we will be using. Start it by ./client 52.23.220.80 6001 10 4096 4096. The
client will receive 10 responses, each having a size of 4096 bytes, from the server.
3. Start RP by ./remote proxy 4. This starts RP with 4 pipes. Also start the server program by
./server 6001 10 if is not yet up. Note the server program and RP are co-located on the same
host.
4. Start LP by ./local proxy 52.23.220.80 4. This starts LP with 4 pipes, and connect them
with the RP. If you run the client program now, the LP and RP programs will not output anything.
This is because the traffic is not yet forwarded to pipes.
5. On the LP host, do sudo perl tm3 mod.pl 52.23.220.80 eth0 6001. Ignore the error message \rmmod: ERROR: Module tm3 is not currently loaded". This will turn on traffic redirection
i.e., redirecting all eth0 traffic from/to server port 6001 to the pipes. In general, the tm3 mod.pl
script is used as follows. The first argument is the public IP address of RP, the second argument
is the name of the primary interface, and the remaining arguments are the server ports whose
redirection will be turned on.
6. Now, run the client again. You will see output produced by LP and RP. This indicates traffic
was being carried by the pipes over port 6000. You can verify that using tcpdump.
7. Stop LP or RP by Ctrl+C.
8. To turn off traffic redirection, do sudo rmmod tm3. If you do not turn off traffic redirection,
your traffic will not be sent out if TM3 is not running.
The second experiment is illustrated in Figure 5 where we use TM3 to fetch data from real web
servers.
1. Start RP with four pipes: ./remote proxy 4
2. Start LP: ./local proxy 52.23.220.80 4
3. On the LP host, enable traffic redirection for port 80 (HTTP) and 443 (HTTPS): sudo perl
tm3 mod.pl 52.23.220.80 eth0 80 443
4. Now open a browser and type a URL. You will see output produced by LP and RP. This indicates
web traffic was being carried by the pipes.
5. Stop LP or RP by Ctrl+C.
6. Turn off traffic redirection by sudo rmmod tm3.
When you run the above experiments, you are also encouraged to use tcpdump and Wireshark to
study the TM3 protocol format. This will help you better understand how TM3 works.

3. Build the TM3 Remote Proxy (RP)

Your RP takes only one argument: the number of pipes. For example, the following command
starts your proxy with 4 pipes (assuming the compiled executable is a.out).
./a.out 4
When your RP starts, listen on port 6000 on n incoming TCP connections from LP where n is the
number of pipes (i.e., four in the above example). After these n pipes are established, your RP can
start processing messages from the LP, or data from remote servers. No pipe message will arrive
before all n pipes are established. Pipes are long-lived. They never close unless LP or RP exits.

Actual Implementation are the following levels

Level 1: Sequential Application Connections over One Pipe
As the minimum requirement, this level lays the groundwork for your work. Your RP should support
sequentially uploading and downloading data that is delivered by one (application) connection over
one pipe. Below are expected behaviors of your RP.
• When receiving a SYN message from LP, establish the connection to the remote server.
• When receiving a data message from LP, extract the data and deliver it to the server.
• When receiving data from the server, encapsulate it into one or more data messages and send
them over the pipe to LP.
• When receiving a FIN message from LP, close the remote connection. You can ignore the
\reason" field in the FIN message.
• When the connection is closed by the server, send a FIN message to LP. Set the \reason" field
correspondingly based on how the connection is closed (0x88 for FIN and 0x99 for RST).

Level 2: Sequential Application Connections over Multiple Pipes
At this level, your RP needs to support multiple pipes. A single application TCP connection is
multiplexed onto multiple pipes
• Select one of the pipes when sending a pipe message to LP. You can use any pipe selection
strategy (e.g., round robin or random). If a pipe is blocked, try another. You only pause sending
when all pipes are blocked. Note a pipe message cannot cross pipes i.e., you cannot send part of it
over one pipe and the other part over another pipe.
• In Level 1, since there is only one pipe, all pipe messages will arrive in order (so the sequence
numbers are not useful). However, when being delivered over multiple pipes, pipe messages can
arrive out-of-order. When this happens, you need to buffer the messages (similar to how TCP
buffers out-of-order segments), and deliver them when the sequence number gap is filled.

Level 3: Concurrent Application Connections over Multiple Pipes
In Level 1 and 2, at any time, there can be at most one active application connection. Now you
are required to support multiple (up to 256) concurrent application connections. The workflow for
each connection is the same as before, but the challenge is to handle the concurrency by carefully
designing your algorithm and data structures. Some of the data structures such as out-of-order
message list and sequence numbers need to be maintained on a per-connection basis.

Level 4: Real Workload over Multiple Pipes
There is no new feature to be added in Level 4. Therefore, if your Level 3 implementation is
perfect, then you will automatically pass this final level. In this level, we will stress test your RP
over real workload. For example, the client host runs a browser that visits real websites, watch a YouTube video, 
or download some very large files. Your code needs to handle diverse situations such as a remote connection fails to 
establish, and a local or remote connection shuts down in the middle of data transmission. Note that throughout 
this project, you may assume that the connectivity between LP and RP never fails. You may also assume the LP never sends
ill-formed pipe messages to RP.

