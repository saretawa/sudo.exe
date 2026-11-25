#pragma once
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char* name;
	const char* description;
	const char* exploit;
} RegistryCheck;

int CheckRegistry();

#ifdef __cplusplus
}
#endif