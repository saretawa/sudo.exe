#include "checks.h"

PathCheckResult checkPath(char* path) {
	PathCheckResult result = { 0 };

	char* lastSlash = strrchr(path, '\\');
	if (lastSlash == NULL) return result;
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

	if (argsStart != NULL) {
		strncpy_s(binPath, MAX_PATH, path, argsStart - path);
	}
	else {
		strcpy_s(binPath, MAX_PATH, path);
	}
	HANDLE cfHandle = CreateFileA(binPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (cfHandle != INVALID_HANDLE_VALUE) {
		result.binaryWritable = 1;
		strcpy_s(result.binPath, MAX_PATH, binPath);
		CloseHandle(cfHandle);
	}
	HANDLE dirHandle = CreateFileA(testFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	if (dirHandle != INVALID_HANDLE_VALUE) {
		result.dirWritable = 1;
		strcpy_s(result.dirPath, MAX_PATH, dirPath);
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
					if (result.gapCount < 10) {
						strcpy_s(result.gapPaths[result.gapCount], MAX_PATH, gapPath);
						result.gapCount++;
					}
					CloseHandle(uqHandle);
					DeleteFileA(gapPath);
				}
			}

		}
	}

	return result;
}