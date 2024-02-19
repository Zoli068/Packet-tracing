#include "Headers.h"

int max_ttl = 30;
int attempts_per_router = 3;
int showing_icmp_hex = 0;
int showing_hostname = 1;
int non_numeric_value = 0;

//Found on the net,that max is 253 ='\0'
char domain_name[254];

//Destination for the packet
sockaddr_in dstAddr;

int main() {	
	// Library initialization
	WSADATA wsaData;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (iResult != 0){

		printf("\n\n");
		printf("WSAStartup failed with error: %d\n", iResult);
		printf("\nHit the enter to exit");

		_getch();

		return -1;
	}

	dstAddr.sin_family = AF_INET;

	int choice;
	int app_end = 1;

	while (app_end) {

		choice = -1;

		system("CLS");
		printf("*******************APP FOR TRACING THE PACKETS*******************\n\n");
		printf("Available options:\n");
		printf("1) Tracing a packet\n");
		printf("2) Changing parameters\n");
		printf("3) Exit\n");
		printf("\nEnter your choice: ");

		if (scanf_s("%d", &choice) != 1) {

			non_numeric_value = 1;

			break;
		}

		system("CLS");


		switch (choice) {
			case 1:

				if (get_the_ip()) {
					system("CLS");
					packet_tracing();
					system("CLS");
				}

				break;

			case 2:

				changing_parameters();

				break;

			case 3:

				app_end = 0;

				break;
		}

		
	}

	system("CLS");

	if (non_numeric_value == 1) {
		printf("You typed non-numeric value, restart the application!\n");
		printf("Or typed to long string for some value\n\n");
	}

	printf("Thanks for using the app!\n");
	printf("Author: Zoltan Lacko\n");
	printf("Github: Zoli068");

	printf("\n\nHit the enter to close the app");

	_getch();

	WSACleanup();

	return 0;
}

int packet_tracing()
{
	int iResult;

	//for the identification,but in the end it won't be necessary
	//we can put here any number for icmp id
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

		printf("\n\n");
		printf("Error with creating the socket with error:%d\n", WSAGetLastError());
		shutdown(&sndSocket);

		return -1;
	}

	//Making our socket to be in non-blocking mode
	unsigned long mode = 1;
	iResult = ioctlsocket(sndSocket, FIONBIO, &mode);

	if (iResult != NO_ERROR) {

		printf("\n\n");
		printf("Error with changing to non-blocking mode with error: %ld\n", iResult);
		shutdown(&sndSocket);

		return -1;
	}

	if (showing_icmp_hex != 0) {

		printf("Our icmp packet in hex format:\n");
		printf("-------------------------------------------------------------------------------");
		print_raw_data((unsigned char*)&icmp_packet, sizeof(ICMPheader));
		printf("\n-------------------------------------------------------------------------------\n");
	}

	char curr_ttl = 0;
	int sockadrr_size = sizeof(sockaddr_in);
	std::chrono::high_resolution_clock::time_point start, end;
	ICMPheader* rcvICMP = NULL;
	int num_of_attempt;
	int selectResult;

	//for finding the hostname
	struct hostent* myHostent;

	//Creating a fd_set for the socket
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(sndSocket, &readfds);

	timeval timeVal;
	timeVal.tv_sec = 1;
	timeVal.tv_usec = 0;

	printf("Our destination is: %s\n", inet_ntoa(dstAddr.sin_addr));

	if (domain_name[0] != 0) {
		printf("Destination domain name: %s", domain_name);
	}

	if (showing_hostname) {
		myHostent = gethostbyaddr((const char*)(&dstAddr.sin_addr), 16, AF_INET);

		if (myHostent != NULL) {
			printf("\nDestination host name: %s", myHostent->h_name);
			myHostent = NULL;
		}
	}

	printf("\n-------------------------------------------------------------------------------\n");
	printf("The route for the packet is:");
	printf("\n-------------------------------------------------------------------------------\n");
	printf("\t  RTT\tIP address");

	if (showing_hostname) {
		printf("        Host name");
	}

	printf("\n-------------------------------------------------------------------------------");

	sockaddr_in routerAddress;
	char rcvBuffer[256];
	int i;

	for (i = 0;i < max_ttl;i++) {

		//routerAddress will be set from recvfrom, and will containe the router IP where TTL went 0
		memset(rcvBuffer, 0, 256);
		memset(&routerAddress, 0, sockadrr_size);

		//changing the TTL value
		curr_ttl++;
		setsockopt(sndSocket, IPPROTO_IP, IP_TTL, &curr_ttl, sizeof(curr_ttl));

		//we'll try attempts_per_router time,and for each response we wait max 1sec,
		// for loop -> attempts_per_router time , select with timeVal -> 1s
		//and if we doesn't get an answer we'll go on, and inc. the TTL
		for (num_of_attempt = 0;(num_of_attempt < attempts_per_router);num_of_attempt++) {

			iResult = sendto(sndSocket, (const char*)&icmp_packet, sizeof(ICMPheader), 0,
				(SOCKADDR*)&dstAddr, sizeof(dstAddr));

			start = std::chrono::high_resolution_clock::now();

			if (iResult == SOCKET_ERROR) {
				printf("\n\n");
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

				printf("\n\n");
				printf("Socket select failed!\n");
				printf("%d", WSAGetLastError());
				shutdown(&sndSocket);

				return -1;
			}
			else {

				iResult = recvfrom(sndSocket, rcvBuffer, 256, NULL, (sockaddr*)&routerAddress, &sockadrr_size);

				end = std::chrono::high_resolution_clock::now();

				if (iResult != SOCKET_ERROR) {
					break;
				}
				else
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK) {
						printf("\n\n");
						printf("Reciving the packets failed with error: %d\n", WSAGetLastError());
						shutdown(&sndSocket);

						return -1;
					}
				}
			}

		}

		//we checking did we got response or not
		if (num_of_attempt < attempts_per_router) {

			printf("\n");

			double rtt_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

			printf("%d:\t%3.0lfms\t%-15s\t  ", i, rtt_time, inet_ntoa(routerAddress.sin_addr));


			if (showing_hostname) {
				myHostent = gethostbyaddr((const char*)(&routerAddress.sin_addr), 16, AF_INET);

				if (myHostent != NULL) {

					printf("%s", myHostent->h_name);

					myHostent = NULL;
				}
			}

			if (memcmp(&routerAddress.sin_addr, &dstAddr.sin_addr, 4) == 0)
			{
				break;
			}
		}
		else {
			printf("\n%d:\t %3s\tNo response", i, "*");
		}
	}

	printf("\n-------------------------------------------------------------------------------");

	if (i >= max_ttl) {
		printf("\nCouldn't reach the destination\n\n");
	}
	else {
		printf("\nSuccessfully reached the destination\n\n");
	}

	shutdown(&sndSocket);

	return 0;
}

void shutdown(SOCKET* socket) {

	if ((*socket) != SOCKET_ERROR)
		closesocket((*socket));

	printf("\nHit the enter to continue");

	_getch();
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

	return (unsigned short)~sum;										//We returning the one's complement, and bcs of that we using ~
}

void print_raw_data(unsigned char* data, int br) {

	int i = 0;

	for (i = 0;i < br;i++) {

		if (i % 16 == 0) {
			printf("\n");
		}

		printf("%02X ", *(data + i));
	}
}

int get_the_ip() {

	int choice = 0;
	int loop_end = 1;
	int i;

	//aaa.bbb.ccc.ddd + '\0'
	char address[16];

	struct hostent* myHostent;

	memset(address, 0, 16);
	memset(domain_name, 0, 254);

	while (loop_end) {

		printf("*********************GETTING THE DESTINATION*********************\n\n");
		printf("Available options:\n");
		printf("1) Enter the IP address\n");
		printf("2) Enter the domain name\n");
		printf("3) Exit\n");
		printf("\nEnter your choice: ");

		if (scanf_s("%d", &choice) != 1) {

			non_numeric_value = 1;

			break;
		}

		system("CLS");

		switch (choice) {
			case 1:

				printf("***********************GETTING THE IP ADDRESS********************\n\n");
				printf("Enter the IP address: ");

				scanf_s("%s", address, 16);

				fflush(stdin);

				address[15] = '/0';

				dstAddr.sin_addr.s_addr = inet_addr(address);

				if (dstAddr.sin_addr.s_addr == INADDR_NONE) {

					printf("\nInvalid IP address\n");
					printf("\nHit the enter to continue");

					_getch();

					return 0;
				}
				else {
					return 1;
				}

				break;

			case 2:

				printf("**********************GETTING THE DOMAIN NAME********************\n\n");
				printf("Enter the domain name: ");

				scanf_s("%s", domain_name, 254);

				fflush(stdin);

				domain_name[253] = '/0';

				myHostent = gethostbyname(domain_name);

				if (myHostent == NULL) {

					printf("\nInvalid domain name\n");
					printf("\nHit the enter to continue");

					_getch();

					return 0;
				}
				else {

					if (myHostent->h_addrtype == AF_INET) {

						inet_ntop(AF_INET, myHostent->h_addr_list[0], address, 16);

						address[15] = '\0';

						for (i = 0; myHostent->h_addr_list[i] != NULL; i++);

						dstAddr.sin_addr.s_addr = inet_addr(address);

						return 1;
					}
					else {

						printf("\n This app works with IPv4 addresses only\n");
						printf("\nHit the enter to continue");

						_getch();

						return 0;
					}

					return 0;
				}

				break;

			case 3:

				loop_end = 0;
				
				break;
		}

		system("CLS");
	}

	return 0;
}

void changing_parameters() {

	int loop_end = 1;
	int choice = 0;

	while (loop_end) {

		system("CLS");

		printf("***********************CHANGING PARAMETERS***********************\n\n");
		printf("Current values:\n");
		printf("MAX TTL:  %d\n", max_ttl);
		printf("MAX ATTEMPTS PER ROUTER:  %d\n", attempts_per_router);
		printf("SHOWING ICMP IN HEX FORMAT: %s\n", (showing_icmp_hex) ? "SHOW" : "HIDE");
		printf("SHOWING THE HOST NAME: %s\n\n", (showing_hostname) ? "SHOW" : "HIDE");
		printf("Available options:\n");
		printf("1) Changing the max TTL value\n");
		printf("2) Changing the max attempts per router\n");
		printf("3) Showing ICMP packet that we using in hex format\n");
		printf("4) Showing the host name\n");
		printf("5) Finish with the changing\n");
		printf("\nEnter your choice: ");

		if (scanf_s("%d", &choice) != 1) {

			non_numeric_value = 1;

			break;
		}

		system("CLS");

		switch (choice) {
			case 1:
				printf("*******************CHANGING THE MAX TTL VALUE********************\n\n");
				printf("Enter the new max TTL value (1-255): ");

				scanf_s("%d", &choice);

				if (choice > 0 && choice < 255) {
					max_ttl = choice;
				}

				break;

			case 2:

				printf("***************CHANGING THE MAX ATTEMPTS PER ROUTER**************\n\n");
				printf("Enter the new value for the max attempts per router (1-10): ");

				scanf_s("%d", &choice);

				if (choice > 0 && choice < 10) {
					attempts_per_router = choice;
				}

				break;

			case 3:

				printf("****************SHOWING ICMP PACKET IN HEX FORMAT****************\n\n");
				printf("Option: 0-Hide");
				printf("\n        1-Show");
				printf("\n\nEnter your choice: ");

				if (scanf_s("%d", &choice) != 1) {

					non_numeric_value = 1;

					break;
				}

				if (choice == 0 || choice == 1) {
					showing_icmp_hex = choice;
				}

				break;

			case 4:

				printf("**********************SHOWING THE HOST NAME**********************\n\n");
				printf("Option: 0-Hide");
				printf("\n        1-Show");
				printf("\n\nEnter your choice: ");


				if (scanf_s("%d", &choice) != 1) {

					non_numeric_value = 1;

					break;
				}

				if (choice == 0 || choice == 1) {
					showing_hostname = choice;
				}

				break;
			case 5:

				loop_end = 0;

				break;
		}
	}
}