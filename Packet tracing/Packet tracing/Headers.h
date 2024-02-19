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
#include <process.h>						

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

struct ICMPheader
{
    unsigned char    byType;
    unsigned char    byCode;
    unsigned short    nChecksum;
    unsigned short    nId;
    unsigned short    nSequence;
};

unsigned short checksum(unsigned short* buffer, int len);
void print_raw_data(unsigned char* data, int br);
void shutdown(SOCKET* socket);
int packet_tracing();
void changing_parameters();
int get_the_ip();