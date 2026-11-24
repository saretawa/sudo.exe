#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <string.h>
#include "checks.h"
#include "tasks.h"

#pragma comment(lib, "wevtapi")

static char* parseField(char* line, char* out, int maxLen) {
    if (line == NULL || *line == '\0' || *line == '\n' || *line == '\r') return NULL;

    int i = 0;
    if (*line == '"') {
        line++;
        while (*line != '\0' && *line != '\n') {
            if (*line == '"') {
                if (*(line + 1) == '"') {
                    if (i < maxLen - 1) out[i++] = '"';
                    line += 2;
                }
                else {
                    line++;
                    if (*line == ',') line++;
                    break;
                }
            }
            else {
                if (i < maxLen - 1) out[i++] = *line;
                line++;
            }
        }
    }
    else {
        while (*line != '\0' && *line != '\n' && *line != '\r' && *line != ',') {
            if (i < maxLen - 1) out[i++] = *line;
            line++;
        }
        if (*line == ',') line++;
    }
    out[i] = '\0';
    return line;
}

static char* extractTag(char* xml, const char* openTag, const char* closeTag, char* out, int maxLen) {
    char* start = strstr(xml, openTag);
    if (start == NULL) return NULL;
    start += strlen(openTag);
    char* end = strstr(start, closeTag);
    if (end == NULL) return NULL;
    int len = (int)(end - start);
    if (len >= maxLen) len = maxLen - 1;
    strncpy_s(out, maxLen, start, len);
    return out;
}

static void checkTaskFolder(char* folderPath, char* username) {
    char searchPath[MAX_PATH];
    strcpy_s(searchPath, MAX_PATH, folderPath);
    strcat_s(searchPath, MAX_PATH, "\\*");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;

        char fullPath[MAX_PATH];
        strcpy_s(fullPath, MAX_PATH, folderPath);
        strcat_s(fullPath, MAX_PATH, "\\");
        strcat_s(fullPath, MAX_PATH, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            checkTaskFolder(fullPath, username);
            continue;
        }

        int xmlWritable = 0;
        HANDLE wh = CreateFileA(fullPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (wh != INVALID_HANDLE_VALUE) {
            xmlWritable = 1;
            CloseHandle(wh);
        }

        HANDLE rh = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (rh == INVALID_HANDLE_VALUE) {
            if (xmlWritable) {
                printf("[*] [%s] Task XML is writable (could not read to extract binary)\n", fd.cFileName);
            }
            continue;
        }

        DWORD fileSize = GetFileSize(rh, NULL);
        if (fileSize == 0 || fileSize > 1048576) {
            CloseHandle(rh);
            continue;
        }

        char* xml = (char*)malloc(fileSize + 1);
        if (xml == NULL) {
            CloseHandle(rh);
            continue;
        }

        DWORD bytesRead = 0;
        ReadFile(rh, xml, fileSize, &bytesRead, NULL);
        CloseHandle(rh);
        xml[bytesRead] = '\0';

        char command[MAX_PATH] = { 0 };
        char userId[256] = { 0 };

        extractTag(xml, "<Command>", "</Command>", command, MAX_PATH);
        extractTag(xml, "<UserId>", "</UserId>", userId, 256);

        free(xml);

        if (command[0] == '\0') continue;
        if (strstr(userId, username) != NULL) continue;

        char expanded[MAX_PATH];
        ExpandEnvironmentStringsA(command, expanded, MAX_PATH);
        strcpy_s(command, MAX_PATH, expanded);

        if (xmlWritable) {
            printf("[*] [%s] Task XML is writable: %s\n", fd.cFileName, fullPath);
            if (userId[0] != '\0') printf("    Runs as: %s\n", userId);
        }

        PathCheckResult result = checkPath(command);

        if (result.binaryWritable) {
            printf("[*] [%s] Task Has Writable binary: %s\n", fd.cFileName, result.binPath);
            if (userId[0] != '\0') printf("    Runs as: %s\n", userId);
        }
        if (result.dirWritable) {
            printf("[*] [%s] Task Has Writable task directory: %s\n", fd.cFileName, result.dirPath);
            if (userId[0] != '\0') printf("    Runs as: %s\n", userId);
        }
        if (result.gapCount > 0) {
            for (int g = 0; g < result.gapCount; g++) {
                printf("[*] [%s] Task Has Unquoted Gap: %s\n", fd.cFileName, result.gapPaths[g]);
                if (userId[0] != '\0') printf("    Runs as: %s\n", userId);
            }
        }

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

// Dedup tracker for event log paths
#define EVT_DEDUP_MAX 256

static int evtDedupCount = 0;
static char evtDedupPaths[EVT_DEDUP_MAX][MAX_PATH];

static int evtAlreadySeen(const char* path) {
    for (int i = 0; i < evtDedupCount; i++) {
        if (_stricmp(evtDedupPaths[i], path) == 0) return 1;
    }
    return 0;
}

static void evtAddSeen(const char* path) {
    if (evtDedupCount < EVT_DEDUP_MAX) {
        strcpy_s(evtDedupPaths[evtDedupCount], MAX_PATH, path);
        evtDedupCount++;
    }
}

static void checkEventLog(char* username) {
    EVT_HANDLE hQuery = EvtQuery(
        NULL,
        L"Microsoft-Windows-TaskScheduler/Operational",
        L"*[System[EventID=200]]",
        EvtQueryChannelPath | EvtQueryReverseDirection
    );

    if (hQuery == NULL) return;

    EVT_HANDLE hEvents[50];
    DWORD returned = 0;

    while (EvtNext(hQuery, 50, hEvents, 2000, 0, &returned)) {
        for (DWORD i = 0; i < returned; i++) {
            DWORD bufSize = 0;
            DWORD propCount = 0;
            EvtRender(NULL, hEvents[i], EvtRenderEventXml, 0, NULL, &bufSize, &propCount);

            if (bufSize == 0) {
                EvtClose(hEvents[i]);
                continue;
            }

            WCHAR* xmlBuf = (WCHAR*)malloc(bufSize);
            if (xmlBuf == NULL) {
                EvtClose(hEvents[i]);
                continue;
            }

            if (!EvtRender(NULL, hEvents[i], EvtRenderEventXml, bufSize, xmlBuf, &bufSize, &propCount)) {
                free(xmlBuf);
                EvtClose(hEvents[i]);
                continue;
            }

            int mbLen = WideCharToMultiByte(CP_UTF8, 0, xmlBuf, -1, NULL, 0, NULL, NULL);
            if (mbLen <= 0) {
                free(xmlBuf);
                EvtClose(hEvents[i]);
                continue;
            }

            char* xmlMb = (char*)malloc(mbLen);
            if (xmlMb == NULL) {
                free(xmlBuf);
                EvtClose(hEvents[i]);
                continue;
            }

            WideCharToMultiByte(CP_UTF8, 0, xmlBuf, -1, xmlMb, mbLen, NULL, NULL);
            free(xmlBuf);

            char taskName[512] = { 0 };
            char actionName[MAX_PATH] = { 0 };

            char* tn = strstr(xmlMb, "Name='TaskName'>");
            if (tn != NULL) {
                tn += strlen("Name='TaskName'>");
                char* tnEnd = strstr(tn, "</Data>");
                if (tnEnd != NULL) {
                    int tnLen = (int)(tnEnd - tn);
                    if (tnLen >= (int)sizeof(taskName)) tnLen = sizeof(taskName) - 1;
                    if (tnLen > 0) memcpy(taskName, tn, tnLen);
                    taskName[tnLen] = '\0';
                }
            }

            char* an = strstr(xmlMb, "Name='ActionName'>");
            if (an != NULL) {
                an += strlen("Name='ActionName'>");
                char* anEnd = strstr(an, "</Data>");
                if (anEnd != NULL) {
                    int anLen = (int)(anEnd - an);
                    if (anLen >= (int)sizeof(actionName)) anLen = sizeof(actionName) - 1;
                    if (anLen > 0) memcpy(actionName, an, anLen);
                    actionName[anLen] = '\0';
                }
            }

            free(xmlMb);
            EvtClose(hEvents[i]);

            if (actionName[0] == '\0') continue;

            char expanded[MAX_PATH];
            ExpandEnvironmentStringsA(actionName, expanded, MAX_PATH);
            strcpy_s(actionName, MAX_PATH, expanded);

            if (evtAlreadySeen(actionName)) continue;
            evtAddSeen(actionName);

            PathCheckResult result = checkPath(actionName);

            if (result.binaryWritable) {
                printf("[*] [%s] Task Has Writable binary (event log): %s\n",
                    taskName[0] ? taskName : "unknown", result.binPath);
            }
            if (result.dirWritable) {
                printf("[*] [%s] Task Has Writable task directory (event log): %s\n",
                    taskName[0] ? taskName : "unknown", result.dirPath);
            }
            if (result.gapCount > 0) {
                for (int g = 0; g < result.gapCount; g++) {
                    printf("[*] [%s] Task Has Unquoted Gap (event log): %s\n",
                        taskName[0] ? taskName : "unknown", result.gapPaths[g]);
                }
            }
        }
    }

    EvtClose(hQuery);
}

static void checkLegacyTasksFolder(char* username) {
    char legacyDir[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\Tasks", legacyDir, MAX_PATH);

    int folderWritable = 0;
    char testPath[MAX_PATH];
    strcpy_s(testPath, MAX_PATH, legacyDir);
    strcat_s(testPath, MAX_PATH, "\\sudo_test.tmp");
    HANDLE hTest = CreateFileA(testPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTest != INVALID_HANDLE_VALUE) {
        folderWritable = 1;
        CloseHandle(hTest);
        DeleteFileA(testPath);
    }

    if (folderWritable) {
        printf("[*] Legacy task folder is writable: %s\n", legacyDir);
        printf("    Standard users can plant .job files here\n");
    }

    char searchPath[MAX_PATH];
    strcpy_s(searchPath, MAX_PATH, legacyDir);
    strcat_s(searchPath, MAX_PATH, "\\*.job");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        char fullPath[MAX_PATH];
        strcpy_s(fullPath, MAX_PATH, legacyDir);
        strcat_s(fullPath, MAX_PATH, "\\");
        strcat_s(fullPath, MAX_PATH, fd.cFileName);

        int jobWritable = 0;
        HANDLE wh = CreateFileA(fullPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (wh != INVALID_HANDLE_VALUE) {
            jobWritable = 1;
            CloseHandle(wh);
        }

        if (jobWritable) {
            printf("[*] [%s] Legacy .job file is writable: %s\n", fd.cFileName, fullPath);
        }

        HANDLE rh = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (rh == INVALID_HANDLE_VALUE) continue;

        DWORD fileSize = GetFileSize(rh, NULL);
        if (fileSize < 72 || fileSize > 65536) {
            CloseHandle(rh);
            continue;
        }

        BYTE* jobData = (BYTE*)malloc(fileSize);
        if (jobData == NULL) {
            CloseHandle(rh);
            continue;
        }

        DWORD bytesRead = 0;
        ReadFile(rh, jobData, fileSize, &bytesRead, NULL);
        CloseHandle(rh);

        if (bytesRead < 72) {
            free(jobData);
            continue;
        }

        DWORD offset = 68;
        if (offset + 2 > bytesRead) { free(jobData); continue; }
        offset += 2;

        if (offset + 2 > bytesRead) { free(jobData); continue; }
        WORD appNameChars = *(WORD*)(jobData + offset);
        offset += 2;

        if (appNameChars == 0 || offset + appNameChars * 2 > bytesRead) {
            free(jobData);
            continue;
        }

        WCHAR* appNameW = (WCHAR*)(jobData + offset);

        char appName[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_ACP, 0, appNameW, appNameChars, appName, MAX_PATH - 1, NULL, NULL);

        free(jobData);

        if (appName[0] == '\0') continue;

        char expanded[MAX_PATH];
        ExpandEnvironmentStringsA(appName, expanded, MAX_PATH);
        strcpy_s(appName, MAX_PATH, expanded);

        PathCheckResult result = checkPath(appName);

        if (result.binaryWritable) {
            printf("[*] [%s] Legacy task Has Writable binary: %s\n", fd.cFileName, result.binPath);
        }
        if (result.dirWritable) {
            printf("[*] [%s] Legacy task Has Writable directory: %s\n", fd.cFileName, result.dirPath);
        }
        if (result.gapCount > 0) {
            for (int g = 0; g < result.gapCount; g++) {
                printf("[*] [%s] Legacy task Has Unquoted Gap: %s\n", fd.cFileName, result.gapPaths[g]);
            }
        }

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

int checkTasks() {
    char username[256];
    DWORD userLen = 256;
    GetUserNameA(username, &userLen);

    // pass 1: schtasks CSV
    FILE* fp = _popen("schtasks /query /fo CSV /v 2>nul", "r");
    if (fp == NULL) {
        printf("[-] Failed to run schtasks (blocked or unavailable)\n");
    }
    else {
        char line[8192];
        int taskNameCol = -1;
        int taskToRunCol = -1;
        int runAsUserCol = -1;
        int headerParsed = 0;

        while (fgets(line, sizeof(line), fp) != NULL) {
            if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0') continue;

            if (!headerParsed) {
                char field[512];
                char* pos = line;
                int col = 0;
                while (pos != NULL && *pos != '\0' && *pos != '\n') {
                    pos = parseField(pos, field, sizeof(field));
                    if (!strcmp(field, "TaskName")) taskNameCol = col;
                    else if (!strcmp(field, "Task To Run")) taskToRunCol = col;
                    else if (!strcmp(field, "Run As User")) runAsUserCol = col;
                    col++;
                }
                headerParsed = 1;
                if (taskNameCol == -1 || taskToRunCol == -1 || runAsUserCol == -1) {
                    break;
                }
                continue;
            }

            char field[512];
            char taskName[512] = { 0 };
            char taskToRun[MAX_PATH] = { 0 };
            char runAsUser[256] = { 0 };
            char* pos = line;
            int col = 0;

            while (pos != NULL && *pos != '\0' && *pos != '\n') {
                pos = parseField(pos, field, sizeof(field));
                if (col == taskNameCol) strcpy_s(taskName, sizeof(taskName), field);
                else if (col == taskToRunCol) strcpy_s(taskToRun, sizeof(taskToRun), field);
                else if (col == runAsUserCol) strcpy_s(runAsUser, sizeof(runAsUser), field);
                col++;
            }

            if (taskToRun[0] == '\0') continue;
            if (!strcmp(taskToRun, "COM handler")) continue;
            if (!strcmp(taskName, "TaskName")) continue;
            if (strstr(runAsUser, username) != NULL) continue;

            char expanded[MAX_PATH];
            ExpandEnvironmentStringsA(taskToRun, expanded, MAX_PATH);
            strcpy_s(taskToRun, MAX_PATH, expanded);

            PathCheckResult result = checkPath(taskToRun);

            if (result.binaryWritable) {
                printf("[*] [%s] Task Has Writable binary: %s\n", taskName, result.binPath);
                printf("    Runs as: %s\n", runAsUser);
            }
            if (result.dirWritable) {
                printf("[*] [%s] Task Has Writable task directory: %s\n", taskName, result.dirPath);
                printf("    Runs as: %s\n", runAsUser);
            }
            if (result.gapCount > 0) {
                for (int g = 0; g < result.gapCount; g++) {
                    printf("[*] [%s] Task Has Unquoted Gap: %s\n", taskName, result.gapPaths[g]);
                    printf("    Runs as: %s\n", runAsUser);
                }
            }
        }

        _pclose(fp);
    }

    // pass 2: direct XML file walk (SharpUp method)
    char tasksDir[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\System32\\Tasks", tasksDir, MAX_PATH);
    checkTaskFolder(tasksDir, username);

    // pass 3: event log mining (TaskScheduler/Operational)
    checkEventLog(username);

    // pass 4: legacy C:\Windows\Tasks folder
    checkLegacyTasksFolder(username);

    return 0;
}