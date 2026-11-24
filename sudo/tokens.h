#pragma once
#ifdef __cplusplus
extern "C"{
#endif

typedef struct {
	char name[255];
	char reason[255];
} priv;

extern priv escprivs[];
int checkTokens();

#ifdef __cplusplus
}
#endif