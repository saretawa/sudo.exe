#include "registry.h"

#include <windows.h>

RegistryCheck regChecks[] = {
    {"AlwaysInstallElevated", "HKLM+HKCU both set to 1", "Install malicious MSI as SYSTEM"},
    {"Weak Service Key ACL", "User can modify service ImagePath", "Repoint service binary and gain SYSTEM"},
    {"Autorun Key Target", "Writable binary in Run/RunOnce", "Replace binary, runs at next admin logon"},
    {"Point and Print", "NoWarningNoElevation enabled", "PrintNightmare even when patched"},
    {"RpcEptMapper/Dnscache", "User can create Performance subkey", "Plant DLL loaded as SYSTEM (Win7/2012)"},
    {"TaskCache ACL", "User can modify task action", "Redefine privileged task binary"},
    {"AppInit_DLLs", "LoadAppInit=1 and path writable", "DLL injected into every GUI process"},
    {"Winlogon Shell/Userinit", "Value writable by user", "Hijack admin logon execution"},
    {"IFEO Debugger", "Writable IFEO subkey", "Hijack any privileged binary launch"},
    {"KnownDLLs/SafeDllSearch", "Key writable or SafeMode=0", "DLL search order hijack on privileged processes"},
};

void DisplayInfo(int id, char* addition) {
    if (addition == NULL) {
        printf("[*] [%s] can be abused, because %s, way to abuse it is [%s]\n", regChecks[id].name, regChecks[id].description, regChecks[id].exploit);
    }
    else {
        printf("[*] [%s] can be abused, specificly [%s], because %s, way to abuse it: [%s]\n", regChecks[id].name, addition, regChecks[id].description, regChecks[id].exploit);
    }
}

int CheckRegistry() {
    HKEY hKey;
    BOOL hklmSet = FALSE;
    BOOL hkcuSet = FALSE;
    DWORD val, size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS) {
            if (val == 1) {
                hklmSet = TRUE;
            }
        }
        RegCloseKey(hKey);
    }

    size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS) {
            if (val == 1) {
                hkcuSet = TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    if (hklmSet && hkcuSet) {
        DisplayInfo(0, NULL);
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        char subkey[256] = { 0 };
        DWORD subkeysize = 256;

        while (RegEnumKeyExA(hKey, index, subkey, &subkeysize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            index++;
            subkeysize = 256;
            HKEY hSubKey;

            if (RegOpenKeyExA(hKey, subkey, 0, KEY_SET_VALUE, &hSubKey) == ERROR_SUCCESS) {
                DisplayInfo(1, subkey);
                RegCloseKey(hSubKey);
            }
        }
        RegCloseKey(hKey);
    }
    return 0;
}

