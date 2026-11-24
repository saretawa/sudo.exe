#include <windows.h>

#include "checks.h"
#include "services.h"

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


		if (!strcmp(srvconfig->lpServiceStartName, username)) continue;

		PathCheckResult result = checkPath(path);


		if (result.binaryWritable) {
			printf("[*] [%s] Service Has Overwritable Binary: %s\n", stp[i].lpServiceName, result.binPath);
		}

		if (result.dirWritable) {
			printf("[*] [%s] Service Has Writable service directory: %s\n", stp[i].lpServiceName, result.dirPath);
		}
		if (result.gapCount > 0) {
			for (int g = 0; g < result.gapCount; g++) {
				printf("[*] [%s] Service Has Unquoted Gap: %s\n", stp[i].lpServiceName, result.gapPaths[g]);
			}
		}
		free(srvconfig);
		CloseServiceHandle(srv);
	}
	return 0;
}
