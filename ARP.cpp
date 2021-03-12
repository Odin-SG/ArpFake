#include <iostream>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

int getMacByArp(char* srcIp, char* destIp) {
	DWORD arp;
	IPAddr dest = 0;
	IPAddr src = 0;
	ULONG mac[2];
	ULONG maclen = 6;

	const char* strSrcIp = srcIp;
	const char* strDestIp = destIp;


	inet_pton(AF_INET, strSrcIp, &src);
	inet_pton(AF_INET, strDestIp, &dest);

	memset(&mac, 0xff, sizeof(mac));

	arp = SendARP(dest, src, &mac, &maclen);

	BYTE* bMac = (BYTE*)&mac;

	//printf("%-20s", strDestIp);
	for (int i = 0; i < (int)maclen; i++) {
		if (i == (maclen - 1)) {
			printf("%.2x\n", (int)bMac[i]);
		}
		else {
			printf("%.2x-", (int)bMac[i]);
		}
	}

	return 0;
}

int main(int argc, char *argv[]) {
	int ret;
	if (argv[1] != NULL or argv[1] != "" and argv[2] != NULL or argv[2] != "") {
		ret = getMacByArp(argv[1], argv[2]);
	}
	return ret;
}