#include "services.h"
#include <windows.h>

int checkServices() {
	SC_HANDLE srvHandle = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

	DWORD bufSize = NULL;
	DWORD srvCount = NULL;

	EnumServicesStatusExA(srvHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bufSize, &srvCount, NULL, NULL);

	ENUM_SERVICE_STATUS_PROCESSA* stp = (ENUM_SERVICE_STATUS_PROCESSA*)malloc(bufSize);

	EnumServicesStatusExA(srvHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, stp, bufSize, &bufSize, &srvCount, NULL, NULL);

	char username[256];
	DWORD userLen = 256;

	GetUserNameA(username, &userLen);

	for (int i = 0; i < srvCount; i++) {
		HANDLE srv = OpenServiceA(srvHandle, stp[i].lpServiceName, SERVICE_QUERY_CONFIG);
		DWORD srvbufSize = NULL;

		if (srv == NULL) continue;

		QueryServiceConfigA(srv, NULL, 0, &srvbufSize);

		LPQUERY_SERVICE_CONFIGA srvconfig = (LPQUERY_SERVICE_CONFIGA)malloc(srvbufSize);

		QueryServiceConfigA(srv, srvconfig, srvbufSize, &srvbufSize);

		if (srvconfig->lpBinaryPathName == NULL || srvconfig->lpServiceStartName == NULL) continue;

		char* path = srvconfig->lpBinaryPathName;
		char* lastSlash = strrchr(path, '\\');
		if (lastSlash == NULL) continue;
		int dirLen = lastSlash - path;
		char dirPath[MAX_PATH];
		strncpy_s(dirPath, MAX_PATH, path, dirLen);
		dirPath[dirLen] = '\0';

		char* dotPos = strchr(lastSlash, '.'); //extension dot
		char* argsStart = NULL;
		if (dotPos != NULL) {
			argsStart = strchr(dotPos, ' '); //arg start pos
		}
		char binPath[MAX_PATH];

		char testFile[MAX_PATH];
		strcpy_s(testFile, MAX_PATH, dirPath);
		strcat_s(testFile, MAX_PATH, "\\sudo_test.tmp");

		if (!strcmp(srvconfig->lpServiceStartName, username)) continue;


		if (argsStart != NULL) {
			strncpy_s(binPath, MAX_PATH, path, argsStart - path);
		}
		else {
			strcpy_s(binPath, MAX_PATH, path);
		}
		HANDLE cfHandle = CreateFileA(binPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (cfHandle != INVALID_HANDLE_VALUE) {
			printf("[*] Writable binary: %s\n", binPath);
			CloseHandle(cfHandle);
		}

		HANDLE dirHandle = CreateFileA(testFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
		if (dirHandle != INVALID_HANDLE_VALUE) {
			printf("[*] Writable service directory: %s\n", dirPath);
			CloseHandle(dirHandle);
			DeleteFileA(testFile);
		}


		if (strchr(dirPath, ' ') && path[0] != '"') {
			char gapPath[MAX_PATH];

			for (int j = 0; j < strlen(path); j++) {
				if (path[j] == ' ') {
					strncpy_s(gapPath, MAX_PATH, path, j);
					strcat_s(gapPath, MAX_PATH, ".exe");

					HANDLE uqHandle = CreateFileA(gapPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);

					if (uqHandle != INVALID_HANDLE_VALUE) {
						printf("[*] Writable unquoted path found: %s\n", gapPath);
						CloseHandle(uqHandle);
						DeleteFileA(gapPath);
					}
				}

			}
		}
		free(srvconfig);
		CloseServiceHandle(srv);
	}
	return 0;
}
