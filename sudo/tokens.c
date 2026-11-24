#include "tokens.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

priv escprivs[] = {
	{"SeImpersonatePrivilege", "Potato attacks -> SYSTEM"},
	{"SeAssignPrimaryTokenPrivilege", "Token replacement -> SYSTEM"},
	{"SeDebugPrivilege", "Access any process (LSASS dumping)"},
	{"SeBackupPrivilege", "Read any file, ignore ACLs"},
	{"SeRestorePrivilege", "Write any file, ignore ACLs"},
	{"SeLoadDriverPrivilege", "Load kernel drivers"},
	{"SeTakeOwnershipPrivilege", "Take ownership of any object"},
	{"SeTcbPrivilege", "Act as OS, create tokens"},
	{"SeCreateTokenPrivilege", "Forge tokens directly"},
	{"SeManageVolumePrivilege", "Raw disk read, extract SAM/NTDS"},
	{"SeRelabelPrivilege", "Downgrade integrity labels on objects"},
};

int checkpriv(char name[]) {
	for (int i = 0; i < sizeof(escprivs) / sizeof(escprivs[0]); i++) {
		if (!strcmp(name, escprivs[i].name)) {
			return i;
		}
	}
	return -1;
}

int checkTokens() {

	HANDLE th;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &th);

	TOKEN_ELEVATION telev;
	DWORD elevSize = NULL;
	

	GetTokenInformation(th, TokenElevation, &telev, sizeof(telev), &elevSize);

	if (telev.TokenIsElevated) {
		CloseHandle(th);
		return 1;
	}

	DWORD tbufsize = NULL;

	GetTokenInformation(th, TokenPrivileges, NULL, 0, &tbufsize);

	TOKEN_PRIVILEGES* tpriv = (TOKEN_PRIVILEGES*)malloc(tbufsize);


	GetTokenInformation(th, TokenPrivileges, tpriv, tbufsize, &tbufsize);


	for (int p = 0; p < tpriv->PrivilegeCount; p++) {
		unsigned long namesize = NULL;
		LookupPrivilegeNameA(NULL, &tpriv->Privileges[p].Luid, NULL, &namesize);
		char* name = (char*)malloc(namesize * sizeof(char));
		LookupPrivilegeNameA(NULL, &tpriv->Privileges[p].Luid, name, &namesize);

		int reasonid = checkpriv(name);

		if (tpriv->Privileges[p].Attributes & SE_PRIVILEGE_ENABLED) {
			printf("%s is [enabled] ", name);
			reasonid != -1 ? printf("and can be used for: %s [*]", escprivs[reasonid].reason) : printf("and useless [-]");
		}
		else
		{
			printf("%s is [disabled] ", name);
			reasonid != -1 ? printf("and can be used for: %s [*]", escprivs[reasonid].reason) : printf("and useless [-]");
		}
		printf("\n");
		free(name);
	}
	CloseHandle(th);
	free(tpriv);
	return 0;
}
