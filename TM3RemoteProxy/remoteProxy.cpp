#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/timeb.h>
#include <fcntl.h>
#include <stdarg.h>
#include <poll.h>
#include <iostream>
#include <map>
#include <vector>

using namespace std;

typedef unsigned char BYTE;

#define MAX_CONNECTIONS 256
#define FIN_MSG_SIZE 9
#define MAX_BUFFER_SIZE 32000000
#define MAX_CONCURRENCY_LIMIT 64
#define LP_LISTEN_PORT 6000
#define TM3_PACKET_DATA_SIZE 4096
#define TM3_HEADER_SIZE 8
#define SYN_MSG_SIZE 14

#define M_CLOSED 0
#define M_OPEN 1

enum Msg_Type{
	data_msg,
	rst_msg,
	fin_msg
};

//Data structure used from Professor's server.cpp
//Stores connection Statistics of a single connection
struct CONN_STAT {
	unsigned int nRecv;
	unsigned int nSent;
	BYTE * buffer;
};

int connectionCount;

//Maps connection ID and a connection
map<uint16_t, struct Con> connectionMap;
//Maps Socket fd and Connection ID
map<int, uint16_t> fdToConnMap;
//Maps a pipe and it's fd
map<int, struct Pipe> fdToPipeMap;


struct Con{
	char ip[INET_ADDRSTRLEN];
	uint16_t port;
	uint16_t connId;
	int fd;
	uint32_t rpSequenceNum;
	int lastSequenceNum;
	int maxSequenceNum;
	struct CONN_STAT connStat;
	map<int,BYTE*> seqToDataMap;
};

struct Pipe{
	int id;
	int fd;
	int nCons;
	struct CONN_STAT connStat;
};

//Method used from Professor's server.cpp code
void Error(const char * format, ...) {
	char msg[TM3_PACKET_DATA_SIZE];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "Error: %s\n", msg);
	exit(-1);
}

//Method used from Professor's server.cpp code
void Log(const char * format, ...) {
	char msg[2048];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "%s\n", msg);
}

//Method used from Professor's server.cpp code
int Send_NonBlocking(int sockFD, const BYTE * data,unsigned int len, struct CONN_STAT * pStat, struct pollfd * pPeer) {

	while (pStat->nSent < len) {
		int n = send(sockFD, data + pStat->nSent, len - pStat->nSent, 0);
		if (n >= 0) {
			pStat->nSent += n;
		} else if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) {
			Log("Connection closed.");
			return -1;
		} else if (n < 0 && (errno == EWOULDBLOCK)) {
			pPeer->events |= POLLWRNORM;
			return 0;
		} else {
			Log("Unexpected send error %d: %s", errno, strerror(errno));
			return -2;
		}
	}
	pPeer->events &= ~POLLWRNORM;
	return 0;
}

//Method used from Professor's server.cpp code
int Recv_NonBlocking(int sockFD, BYTE * data, unsigned int len, struct CONN_STAT * pStat, struct pollfd * pPeer) {
	while (pStat->nRecv < len) {
		int n = recv(sockFD, data + pStat->nRecv, len - pStat->nRecv, 0);
		if (n > 0) {
			pStat->nRecv += n;
		} else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
			Log("Connection closed. %d",errno);
			if(fdToConnMap.count(sockFD)==0) {
				close(sockFD);
				Error("LP Closed");
			}
			return -1;
		} else if (n < 0 && (errno == EWOULDBLOCK)) {
			return 0;
		} else {
			Log("Unexpected recv error %d: %s.", errno, strerror(errno));
		}
	}

	return 0;
}

//Method used from Professor's server.cpp code
void SetNonBlockIO(int fd) {
	int val = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, val | O_NONBLOCK) != 0) {
		Error("Cannot set nonblocking I/O.");
	}
}

//Method used from Professor's server.cpp code
void RemoveConnection(int i,pollfd * peers,CONN_STAT * connStat) {
	if(fdToPipeMap.count(peers[i].fd)==0) {
		close(peers[i].fd);
		if (i < connectionCount) {
			memmove(peers + i, peers + i + 1, (connectionCount-i) * sizeof(struct pollfd));
			memmove(connStat + i, connStat + i + 1, (connectionCount-i) * sizeof(struct CONN_STAT));
		}
		connectionCount--;
	}
}

Pipe selectPipe(vector<Pipe> pipes) {
	return pipes[0];
}


void storeConnID(BYTE * buffer,uint16_t connId){
    buffer[0]=connId & 0xff;
	buffer[1]=connId>>8;
}

void storeSequenceNumber(BYTE * buffer, uint32_t seqNum){
    buffer[2]=seqNum & 0xff;
	buffer[3]=(seqNum>>8) & 0xff;
	buffer[4]=(seqNum>>16) & 0xff;
	buffer[5]=seqNum>>24;
}

void storeMessageLength(BYTE * buffer, unsigned int length){
    buffer[6]=length & 0xff;
	buffer[7]=length>>8;
}

uint16_t getConnId(BYTE * buffer){
    return (buffer[1]) << 8 | buffer[0];
}

uint32_t getSequenceNumber(BYTE * buffer){
    return buffer[5] << 24 | buffer[4] << 16 | buffer[3] << 8 | buffer[2];
}

uint16_t getMsgLength(BYTE * buffer){
    return (buffer[7])<<8|buffer[6];
}

BYTE * createFinPacket(Msg_Type finType, uint16_t connId,uint32_t seqNum) {
	//Buffer containing the single packet. Needs to be freed at callee
	BYTE * finPacket = (BYTE *)malloc(FIN_MSG_SIZE);
	BYTE * data = (BYTE *)malloc(FIN_MSG_SIZE-TM3_HEADER_SIZE);
	unsigned short len=0xfffe;

	if(finType==fin_msg)
		data[0]=0x88;
    else if(finType==rst_msg)
		data[0]=0x99;

    storeConnID(finPacket,connId);
	storeSequenceNumber(finPacket,seqNum);
	storeMessageLength(finPacket,len);

	memcpy(finPacket + TM3_HEADER_SIZE,data,FIN_MSG_SIZE-TM3_HEADER_SIZE);// first 8 bytes is header

	free(data);
	data=NULL;

	return finPacket;

}


//Method to create a single data TM3 packet
BYTE * createDataPacket(uint16_t connId,uint32_t seqNum, unsigned int dataLength, BYTE * data) {

	//Buffer containing the single packet. Needs to be freed at callee
	BYTE * singlePacket = (BYTE *)malloc(8+dataLength);
	int i=0;

	storeConnID(singlePacket,connId);
	storeSequenceNumber(singlePacket,seqNum);
	storeMessageLength(singlePacket,dataLength+TM3_HEADER_SIZE);
	memcpy(singlePacket + TM3_HEADER_SIZE,data, dataLength);// first 8 bytes is header

	return singlePacket;
}

//Method to split data msg from server to TM3 Packet size
void makeTM3Packets(Con *connection,int headerCount,int recvFlag,int pipeCount,pollfd *peers,CONN_STAT * pipeConnStat,CONN_STAT * connStat,int index){


	unsigned int len = connection->connStat.nRecv;
	int pipeID = 0;

	for(int i=0;i<len;i+=TM3_PACKET_DATA_SIZE,pipeID++){

		if(pipeID == pipeCount) {
			pipeID =0;
		}
		int tempLength = TM3_PACKET_DATA_SIZE;
		if(len-i<TM3_PACKET_DATA_SIZE)
			tempLength=len-i;
		BYTE * tempDataMessage = createDataPacket(connection->connId,connection->rpSequenceNum++,tempLength, connection->connStat.buffer+i);
		memcpy(pipeConnStat[pipeID].buffer+pipeConnStat[pipeID].nRecv,tempDataMessage,tempLength+8);
		pipeConnStat[pipeID].nRecv+=(tempLength+8);
		free(tempDataMessage);
		tempDataMessage=NULL;
	}

	if(pipeID == pipeCount)
		pipeID =0;

	if (recvFlag == -1) {//Remote server has closed connection so send fin

        BYTE * tempFinMsg = createFinPacket(fin_msg, connection->connId,connection->rpSequenceNum++);
		memcpy(pipeConnStat[pipeID].buffer+pipeConnStat[pipeID].nRecv,tempFinMsg,FIN_MSG_SIZE);
		pipeConnStat[pipeID].nRecv+=FIN_MSG_SIZE;

		free(tempFinMsg);
		tempFinMsg=NULL;

        //Connection ends with this FIN message. So Cleaning up.
		RemoveConnection(index,peers,connStat);
		fdToConnMap.erase(connection->fd);
		connectionMap.erase(connection->connId);
	}

	//Sending TM3 packets in the pipes in a round robin fashion
	for(int j;j<pipeCount;j++) {
		int sentFlag = Send_NonBlocking(peers[j].fd, pipeConnStat[j].buffer, pipeConnStat[j].nRecv, &pipeConnStat[j], &peers[j]);
		if(sentFlag <0){
			Log("Issues sending data to LP");
		} else {
			if(pipeConnStat[j].nRecv == pipeConnStat[j].nSent) {
				//If data sent == data received then reset the buffer.
				pipeConnStat[j].nSent = 0;
				pipeConnStat[j].nRecv = 0;
			}

		}

	}
}

uint16_t getPort(BYTE * buffer){
    return  buffer[13] << 8 | buffer[12];
}

uint32_t getIP(BYTE * buffer){
    return  buffer[8] << 24 | buffer[9] << 16 | buffer[10] << 8 | buffer[11];
}


void tm3DataHandler(BYTE * tm3Packet, uint16_t messageLength, uint16_t connId,pollfd *peers,CONN_STAT *connStat){

		BYTE * serverBuffer = (BYTE*) malloc(MAX_BUFFER_SIZE);
		memcpy( serverBuffer, &tm3Packet[TM3_HEADER_SIZE], messageLength );

		if(connectionMap.count(connId) > 0) {

			if(connectionMap[connId].port != 0 ) {
				int fd = connectionMap[connId].fd;

				peers[connectionCount].fd = fd;
				peers[connectionCount].events = POLLRDNORM;
				peers[connectionCount].revents = 0;

				memset(&connStat[connectionCount], 0, sizeof(struct CONN_STAT));

				if(Send_NonBlocking(fd, serverBuffer,messageLength, &connStat[connectionCount], &peers[connectionCount]) < 0) {
					Log("Error in sending to Remote server");
				}
				connectionCount++;
			} else {//This case is when connection to server is not established

			}
		} else {//This case is when server is unable to receive the sent data

		}

		free(serverBuffer);
		serverBuffer=NULL;



}

void tm3SynHandler(BYTE * tm3Packet, vector<Pipe> pipes, uint16_t connId, pollfd *peers){

    uint16_t port = getPort(tm3Packet);
    uint32_t ip = getIP(tm3Packet);
    struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(struct sockaddr_in));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((uint16_t) port);
	serverAddr.sin_addr.s_addr = htonl(ip);
	char ipAddressStr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &serverAddr.sin_addr, ipAddressStr, INET_ADDRSTRLEN);
	Log("Connect to remote server: %s:%d",ipAddressStr,port);
	// Create new socket for connecting to the remote server
	int sockFD = socket(AF_INET, SOCK_STREAM, 0);
	if (sockFD == -1) {
		Error("Cannot create socket.");
	}
	//Connect to server
	if (connect(sockFD, (const struct sockaddr *) &serverAddr, sizeof(serverAddr)) == -1) {
		Log("Cannot connect to server %s:%d.", ipAddressStr, port);
		Pipe pipe = selectPipe(pipes);
		CONN_STAT tempConnection;
		tempConnection.nSent=0;
        BYTE * tempFinMsg = createFinPacket(rst_msg, connId,0);
		Send_NonBlocking(pipe.fd,tempFinMsg,FIN_MSG_SIZE, &tempConnection, &peers[pipe.id]);

        free(tempFinMsg);
        tempFinMsg=NULL;
	} else {
		SetNonBlockIO(sockFD);
		int optval = 1;
		int r = setsockopt(sockFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		if (r != 0) {
			Log("Cannot enable SO_REUSEADDR option.");
		}

		strcpy(connectionMap[connId].ip , ipAddressStr);
		connectionMap[connId].port = port;
		connectionMap[connId].rpSequenceNum=0;
		connectionMap[connId].fd = sockFD;
		fdToConnMap.insert(pair<int, uint16_t>(sockFD, connId));
		Log("Connection Established");
	}

}

void tm3FinHandler(uint16_t connId){

		if(connectionMap.count(connId) > 0) {
			int fd = connectionMap[connId].fd;
			close(fd);
			if(fdToConnMap.count(fd) == 0) {
				fdToConnMap.erase(fd);
			}
			if(connectionMap.count(connId) == 0) {
				connectionMap.erase(connId);
			}
		}

}

//This will handle single TM3 packet and forward to server
void tm3PacketHandler(BYTE * tm3Packet,pollfd *peers,CONN_STAT *connStat,vector<Pipe> pipes) {

	uint16_t messageLength = getMsgLength(tm3Packet);
	uint16_t connId = getConnId(tm3Packet);

	if (messageLength <= TM3_PACKET_DATA_SIZE) //Data Message from LP
        tm3DataHandler(tm3Packet,messageLength-TM3_HEADER_SIZE,connId,peers,connStat);
    else if (messageLength == 65534) //Fin Message from LP
        tm3FinHandler(connId);
    else if (messageLength == 65535)
		tm3SynHandler(tm3Packet,pipes,connId,peers);
}

vector<BYTE *> validateSequence(Con *connection,int sequenceNum) {

	vector<BYTE *> packetSequenced;
	int missSeqFlag = 0;
    uint32_t i;

    if(connection->maxSequenceNum<sequenceNum)
        connection->maxSequenceNum =sequenceNum;

	for(i=0;i<=sequenceNum;i++) {
		if(connection->seqToDataMap.count(i)== 0) {
			missSeqFlag = 1;
			break;
		}
	}

    if(missSeqFlag == 0) {
        for(i=connection->lastSequenceNum+1;i<=connection->maxSequenceNum;i++) {
				if(connection->seqToDataMap.count(i)!=0){
					packetSequenced.insert(packetSequenced.end(),connection->seqToDataMap[i]);
					connection->lastSequenceNum = i;
				} else {
					break;
				}
			}
		}
    return packetSequenced;
}


//Method to handle out of order sequence packets from LP
vector<BYTE *> handleSequence(BYTE * pipeBuffer,uint16_t messageLength) {
	map<uint32_t,BYTE*> seqToDataMap;


	uint16_t connId = getConnId(pipeBuffer);


	uint16_t size = messageLength;
	BYTE * tempData = (BYTE *)malloc(size);
	memcpy(tempData,pipeBuffer,size);

    uint32_t sequenceNum=getSequenceNumber(tempData);


	if(connectionMap.count(connId) != 0) {

		connectionMap[connId].seqToDataMap.insert(pair<uint32_t,BYTE *>(sequenceNum ,tempData));
		return validateSequence(&connectionMap[connId],sequenceNum );
	} else {
		struct Con con;
		con.connId = connId;
		con.port = 0;
		con.fd = -1;
		con.rpSequenceNum=0;
		con.lastSequenceNum = -1;
		con.maxSequenceNum = -1;
		con.seqToDataMap.insert(pair<uint32_t,BYTE *>(sequenceNum,tempData));
		connectionMap.insert(pair<uint16_t, struct Con>(connId, con));
		return validateSequence(&connectionMap[connId],sequenceNum );
	}


}

//Parses incoming method from LP
void parseMessage(BYTE * pipeBuffer,pollfd * peers,CONN_STAT *connStat,vector<Pipe> pipes,int totalBufferSize){

    uint16_t messageLength = getMsgLength(pipeBuffer);

	//Condition for a single packet
	if(( messageLength <= TM3_PACKET_DATA_SIZE  && messageLength == totalBufferSize ) || (messageLength ==65534 && totalBufferSize== FIN_MSG_SIZE) || (messageLength ==65535 && totalBufferSize== SYN_MSG_SIZE) ){
		//Vector to store packet in sequence
		vector<BYTE *> packetSequenced = handleSequence(pipeBuffer,totalBufferSize);
		for(int i=0;i<packetSequenced.size();i++)
			tm3PacketHandler(packetSequenced[i],peers,connStat,pipes);

        return ;
	}

	//For Multiple packets
	for(int i=0;i<totalBufferSize;){

        uint16_t tempLength = getMsgLength(pipeBuffer+i);
        if(tempLength==65535){
            tempLength=SYN_MSG_SIZE;
        }else if(tempLength==65534){
            tempLength=FIN_MSG_SIZE;
        }

        BYTE * tempBuf = (BYTE*) malloc(tempLength);
        memcpy(tempBuf,pipeBuffer+i, tempLength);
        vector<BYTE *> packetSequenced = handleSequence(tempBuf,tempLength);

        for(int j=0;j<packetSequenced.size();j++) {
            tm3PacketHandler(packetSequenced[j],peers,connStat,pipes);
        }
        i+=tempLength;
	}

}

void printSocketAddress(int fd) {
	struct sockaddr_in serverAddr;
	socklen_t len = sizeof(serverAddr);
	if (getsockname(fd, (struct sockaddr *)&serverAddr, &len) == -1){
	    perror("getsockname");
	}
	else {
	    printf("port number ::%d\n", ntohs(serverAddr.sin_port));
	}
}

//Sections of the method obtained from professor's server.cpp
int setListenSocket(pollfd *listeningSocket){

    int listenFD = socket(AF_INET, SOCK_STREAM, 0);
    memset(listeningSocket, 0, sizeof(listeningSocket));
	if (listenFD < 0) {
		Error("Cannot create listening socket.");
	}
	SetNonBlockIO(listenFD);
	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(struct sockaddr_in));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((uint16_t) LP_LISTEN_PORT);
	int optval = 1;
	int r = setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (r != 0) {
		Error("Cannot enable SO_REUSEADDR option.");
	}
	if (bind(listenFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
		Error("Cannot bind to port %d.", ntohs(serverAddr.sin_port));
	}
	if (listen(listenFD, 16) != 0) {
		Error("Cannot listen to port %d.", ntohs(serverAddr.sin_port));
	}
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	memset(listeningSocket, 0, sizeof(listeningSocket));
	listeningSocket[0].fd = listenFD;
	listeningSocket[0].events = POLLRDNORM;

    return listenFD;
}

//Sections of method obtained from professor's server.cpp file
vector<Pipe> createPipes(int pipeCount,pollfd *peers,CONN_STAT *connStat,CONN_STAT *connStatO) {
	vector<Pipe> pipes;

	int nConns=0;
	struct pollfd listeningSocket[1];
	int listenFD = setListenSocket(listeningSocket);

	while(1) {
		int nReady = poll(listeningSocket, 1, -1);
		if (nReady < 0) {
			Error("Invalid poll() return value.");
		}
		struct sockaddr_in clientAddr;
		socklen_t clientAddrLen = sizeof(clientAddr);
		if ((listeningSocket[0].revents & POLLRDNORM)) {
			int fd = accept(listenFD, (struct sockaddr *)&clientAddr, &clientAddrLen);
            Log("[INFO] Pipe %d established. Local port=%d, TCP=default",nConns+1,ntohs(clientAddr.sin_port));
			if (fd != -1) {
				Pipe pipe;
				pipe.id = nConns;
				pipe.fd = fd;
				fdToPipeMap.insert(pair<int, struct Pipe>(fd, pipe));
				SetNonBlockIO(fd);
				pipes.insert(pipes.end(), pipe);
				peers[nConns].fd = fd;
				peers[nConns].events = POLLRDNORM;
				peers[nConns].revents = 0;
				memset(&connStat[nConns], 0, sizeof(struct CONN_STAT));
				memset(&connStatO[nConns], 0, sizeof(struct CONN_STAT));
				if(nConns == pipeCount-1) break;
				nConns++;
			}
		}
	}
	int i;
	for (i=0;i<=pipeCount;i++) {
		connStatO[i].buffer = (BYTE*) malloc(MAX_BUFFER_SIZE);
	}

	return pipes;
}

void DoRemoteProxy(int pipeCount) {

	struct pollfd peers[MAX_CONNECTIONS];
	struct CONN_STAT connStat[MAX_CONNECTIONS];
	struct CONN_STAT connStatO[MAX_CONNECTIONS];
	vector<Pipe> pipes = createPipes(pipeCount,peers,connStat,connStatO);
	connectionCount = pipeCount;
	Log("[INFO] Remote proxy on");


	while (1) {

    int incomingConns = poll(peers, connectionCount, -1);
    BYTE * buf = (BYTE*) malloc(MAX_BUFFER_SIZE);

    if (incomingConns > 0) {
        for (int i=0; i<connectionCount; i++) {

            if (peers[i].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
                int fd = peers[i].fd;
                if(fdToConnMap.count(fd)>0) { // Data received from remote Server Socket
                    connectionMap[fdToConnMap[fd]].connStat.buffer = (BYTE *) malloc(MAX_BUFFER_SIZE); // Structure can be changed
                    connectionMap[fdToConnMap[fd]].connStat.nRecv = 0;
                    int recvFlag = Recv_NonBlocking(fd, connectionMap[fdToConnMap[fd]].connStat.buffer, MAX_BUFFER_SIZE,&connectionMap[fdToConnMap[fd]].connStat, &peers[i]);
                    int headerCount;
                    if(connectionMap[fdToConnMap[fd]].connStat.nRecv%TM3_PACKET_DATA_SIZE==0)
                        headerCount=connectionMap[fdToConnMap[fd]].connStat.nRecv/TM3_PACKET_DATA_SIZE;
                    else
                        headerCount=connectionMap[fdToConnMap[fd]].connStat.nRecv/TM3_PACKET_DATA_SIZE + 1;

                    makeTM3Packets(&connectionMap[fdToConnMap[fd]], headerCount,recvFlag,pipeCount,peers,connStatO,connStat,i);
                } else { // Data received from LP Socket
                    connStat[i].nRecv = 0;
                    int recvFlag = Recv_NonBlocking(fd, buf, MAX_BUFFER_SIZE,&connStat[i], &peers[i]);
                    if (recvFlag < 0) {
                        if(connStat[i].nRecv == 0) {
                        //Legacy Code
                        } else {
                            parseMessage(buf,peers,connStat,pipes,connStat[i].nRecv);
                        }
                    } else {
                        parseMessage(buf,peers,connStat,pipes,connStat[i].nRecv);
                    }
                }
            }

            if (peers[i].revents & POLLWRNORM){
                int sentFlag = Send_NonBlocking(peers[i].fd, connStatO[i].buffer, connStatO[i].nRecv, &connStatO[i], &peers[i]);
                if ( sentFlag == 0 && connStatO[i].nSent == connStatO[i].nRecv) {
                    connStatO[i].nSent = 0;
                    connStatO[i].nRecv = 0;
                } else if (sentFlag == -1 ) {
                    Log("LP Closed");
                } else if (sentFlag == -2){
                    //When this happens
                    }
                }
            }

        incomingConns--;
        }

	}
}
int main(int argc, char * * argv) {

    Log("[INFO] TM3 Remote Proxy - [Kaushik Srinivasan, Krishna Ravichandran]");
    Log("[INFO] Version 20161209");

	if (argc != 2) {
		Log("[INFO] Usage: ./rp [number_of_pipes]");
		return -1;
	}
	int pipeCount = atoi(argv[1]);

	if(pipeCount <=0 ){
    Log("[INFO] %s is an invalid number of pipes", argv[1]);
    return -1;
    }

    Log("[INFO] %d pipes",pipeCount);

	DoRemoteProxy(pipeCount);

	return 0;
}

