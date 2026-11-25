#include <iostream>
#include <windows.h>

#include "tokens.h"
#include "services.h"
#include "tasks.h"
#include "registry.h"

using namespace std;


int main() {
	HANDLE th;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &th);

	cout << "---------------------------|Checking Current Privileges|---------------------------\n";
	if (checkTokens()) {
		cout << "You Are Already Administrator Dummy -_-\n";
		return 0;
	}
	cout << "\n\n";
	cout << "---------------------|Checking Writable/Unquoted Service Paths|---------------------\n";
	if (checkServices()) {
		cout << "Failed To Check Services\n";
		return 0;
	}
	cout << "\n\n";
	cout << "-----------------------|Checking Overwritable Scheduled Tasks|-----------------------\n";
	if (checkTasks()) {
		cout << "Failed To Check Tasks\n";
		return 0;
	}
	cout << "\n\n";
	cout << "-----------------------|Checking Registry For Possible Missconfiguration|-----------------------\n";
	if (CheckRegistry()) {
		cout << "Failed To Check Registry\n";
		return 0;
	}
}