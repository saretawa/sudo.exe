#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <windows.h>

typedef struct {
	int binaryWritable;
	int dirWritable;
	char binPath[MAX_PATH];
	char dirPath[MAX_PATH];
	char gapPaths[10][MAX_PATH];
	int gapCount;
} PathCheckResult;

PathCheckResult checkPath(char* path);

#ifdef __cplusplus
}
#endif