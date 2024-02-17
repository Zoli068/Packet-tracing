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