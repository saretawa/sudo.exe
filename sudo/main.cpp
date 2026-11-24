#include <iostream>
#include <windows.h>

#include "tokens.h"
#include "services.h"

using namespace std;


int main() {
	HANDLE th;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &th);

	cout << "---------------------------|Checking Current Privileges|---------------------------\n";
	if (checkTokens()) {
		cout << "You Are Already Administrator Dummy -_-\n";
		return 0;
	}
	cout << "---------------------|Checking Writable/Unquoted Service Paths|---------------------\n";
	if (checkServices()) {
		cout << "Failed To Check Services\n";
		return 0;
	}
}