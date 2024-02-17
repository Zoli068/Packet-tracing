#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <chrono>
#include "conio.h"
#include "Headers.h"
#include <process.h>						

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

int max_ttl = 30;
int attempts_per_router = 3;
int showing_icmp_hex = 0;
//Destination for the packet
sockaddr_in dstAddr;
int main() {
	dstAddr.sin_addr.s_addr = inet_addr("151.101.0.81");

	while (true) {

		printf("*******************APP FOR TRACING THE PACKETS*******************\n\n");

		printf("Available options:\n");
		printf("1) Tracing a packet\n");
		printf("2) Changing parameters\n");
		printf("1-Changing the max TTL value\n");
		printf("2-Changing the max attempts per router\n");
		packet_tracing();


		printf("\n*****************************************************************");
		break;
	}

	return 0;
}

int packet_tracing()
{
	// Library initialization
	WSADATA wsaData;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (iResult != 0)
	{
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	dstAddr.sin_family = AF_INET;

	//for the identification,but in the end it won't be necessary
	int process_pid = _getpid();

	//Creating the icmp_packet
	ICMPheader icmp_packet;

	icmp_packet.byCode = 0;
	icmp_packet.nSequence = htons(1);
	icmp_packet.byType = 8;
	icmp_packet.nId = htons(process_pid);
	icmp_packet.nChecksum = 0;
	icmp_packet.nChecksum = checksum((unsigned short*)&icmp_packet, sizeof(ICMPheader));

	//Creating the socket for sending and for reciving the packets
	SOCKET sndSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sndSocket == INVALID_SOCKET) {
		printf("Error with creating the socket with error:%d\n", WSAGetLastError());
		shutdown(&sndSocket);
		return -1;
	}

	//Making our socket to be in non-blocking mode
	unsigned long mode = 1;
	iResult = ioctlsocket(sndSocket, FIONBIO, &mode);

	if (iResult != NO_ERROR) {
		printf("Error with changing to non-blocking socket with error: %ld\n", iResult);
		shutdown(&sndSocket);
		return -1;
	}

	if (showing_icmp_hex != 0) {
		printf("Our icmp packet in hex format:");
		print_raw_data((unsigned char*)&icmp_packet, sizeof(ICMPheader));
	}

	char curr_ttl = 0;							
	int sockadrr_size = sizeof(sockaddr_in);
	std::chrono::high_resolution_clock::time_point start, end;
	ICMPheader* rcvICMP = NULL;
	int num_of_attempt;
	int selectResult;

	//Creating a fd_set for the socket
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(sndSocket, &readfds);

	timeval timeVal;					//So,not the best, but will be fairly precise
	timeVal.tv_sec = 1;
	timeVal.tv_usec = 0;

	printf("\nThe route for the packet is:\n");
	printf("\n---------------------------------\n");
	printf(" \tRTT\tIP address");
	printf("\n---------------------------------\n");

	sockaddr_in routerAddress;
	char rcvBuffer[256];

	for (int i = 0;i < max_ttl;i++) {

		//routerAddress will be set from recvfrom, and will containe the router IP where TTL went 0

		memset(rcvBuffer, 0, 256);
		memset(&routerAddress, 0, sockadrr_size);

		curr_ttl++;

		//changing the TTL value
		setsockopt(sndSocket, IPPROTO_IP, IP_TTL, &curr_ttl, sizeof(curr_ttl));

		//we'll try 3 time,and for each response we wait max 1sec,
		// for loop -> 3time , select with timeVal -> 1s
		//and if we doesn't get an answer we'll go on, and inc. the TTL
		for (num_of_attempt = 0;(num_of_attempt < attempts_per_router);num_of_attempt++) {

			iResult = sendto(sndSocket, (const char*)&icmp_packet, sizeof(ICMPheader), 0,
				(SOCKADDR*)&dstAddr, sizeof(dstAddr));

			start = std::chrono::high_resolution_clock::now();

			if (iResult == SOCKET_ERROR) {
				printf("Error at sending the packets with error:%d\n", WSAGetLastError());
				shutdown(&sndSocket);
				return -1;
			}

			selectResult = select(0, &readfds, NULL, NULL, &timeVal);

			if (selectResult == 0) {

				//we have to set every time at timeout bcs after timeout set will be changed
				FD_ZERO(&readfds);
				FD_SET(sndSocket, &readfds);

			}
			else if (selectResult == SOCKET_ERROR) {

				printf("Socket select failed!\n");
				printf("%d", WSAGetLastError());
				shutdown(&sndSocket);
				return -1;

			}
			else {

				iResult = recvfrom(sndSocket, rcvBuffer, 256, NULL, (sockaddr*)&routerAddress, &sockadrr_size);

				end= std::chrono::high_resolution_clock::now();

				
				if (iResult != SOCKET_ERROR) {
					break;
				}
				else
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK) {
						printf("Reciving the packets failed with error: %d\n", WSAGetLastError());
						shutdown(&sndSocket);
						return -1;
					}
				}
			}

		}

		//we checking did we got response or not
		if (num_of_attempt < attempts_per_router) {

			//print_raw_data((unsigned char*)rcvBuffer, 12);																												//does we got Type 11 or 0 (11-TTL exceeded ,0 ping reply)
			printf("\n");

			double rtt_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			
			printf("%d:\t%.0lf\t%s ", i,rtt_time, inet_ntoa(routerAddress.sin_addr));

			if (memcmp(&routerAddress.sin_addr,&dstAddr.sin_addr,4) == 0)
			{
				break;
			}
		}
		else {

			printf("\n%d:\t*\tNo response", i);

		}

	}
	printf("\n---------------------------------");
	shutdown(&sndSocket);
}

void shutdown(SOCKET* socket) {

	if ((*socket) != SOCKET_ERROR)
		closesocket((*socket));

	if (WSACleanup() != 0)
	{
		printf("WSACleanup failed with error: %d\n", WSAGetLastError());
	}

}

unsigned short checksum(unsigned short* buffer, int len)
{
	unsigned long sum = 0;

	while (len > 1) {													//Until we doesn't go trough all the bytes

		sum = sum + *(buffer);											//We summing up the values
		buffer++;

		if (sum & 0x80000000)											//If we got carry bit , then we add 1 to the LSB
			sum = (sum & 0xFFFF) + (sum >> 16);							//Mask to save the original 16bit and addig the carry
		len -= 2;
	}

	if (len)															//If we got 1 more last byte, than we also doing the stuff
		sum += (unsigned short)*(unsigned char*)buffer;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (unsigned short)~sum;										//We returning the one's compilment, and bcs of that we using ~
}


void print_raw_data(unsigned char* data, int br) {						//For developing purpose

	int i = 0;

	for (i = 0;i < br;i++) {

		if (i % 16 == 0) {
			printf("\n");
		}

		printf("%02X ", *(data + i));
	}
}
