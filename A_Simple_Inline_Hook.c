# include <stdio.h>
# include <Windows.h>

// Defines:

# define RETURN_ERROR_INVALID_PARAM_MODULENAME (1)
# define RETURN_ERROR_FAILED_GETTING_FUNCTION_ADDRESS (2)
# define RETURN_ERROR_FAILED_IN_GETTING_ACCESS_TO_GIVEN_FUNCTION (3)
# define RETURN_ERROR_FAILED_IN_RETURNING_ACCESS_TO_GIVEN_FUNCTION (4)
# define RETURN_ERROR_UNSUCCESSFUL_HOOK (5)


// Functions Declarations:
int setHook(wchar_t* pcModuleName, char* pcFunctionName, void* pNewFunction);
BOOL WINAPI pNewFunction(HANDLE hObject);

int main()
{
	int result = ERROR_SUCCESS;
	int iSettingHookResult = 0;
	HANDLE hFakeHandle = NULL;

	// Now we'll set the hook
	iSettingHookResult = setHook(L"kernel32.dll", "CloseHandle", pNewFunction);
	if (ERROR_SUCCESS != iSettingHookResult)
	{
		return RETURN_ERROR_UNSUCCESSFUL_HOOK;
	}

	// Let's simulate the hook action:
	hFakeHandle = (HANDLE) 0x1337;
	result = CloseHandle(hFakeHandle);

	return ERROR_SUCCESS;
}

int setHook(wchar_t* pcModuleName, char* pcFunctionName, void* pNewFunction)
{
	INT_PTR diff = 0;
	DWORD dwOldProtect = 0;
	int iProtection = NULL;
	DWORD dwOldProtect2 = 0;
	PBYTE iOldFunctionAddr = NULL;
	HANDLE hHandleToModule = NULL;

	hHandleToModule = GetModuleHandleW(pcModuleName);
	if (NULL == hHandleToModule)
	{
		printf("Error in function setHook: invalid parameter pcModuleName. exiting...");
		return RETURN_ERROR_INVALID_PARAM_MODULENAME;
	}

	iOldFunctionAddr = GetProcAddress(hHandleToModule, pcFunctionName);
	if (NULL == iOldFunctionAddr)
	{
		printf("Error in function setHook: Wasn't successful in getting the address of the given function. exiting...");
		return RETURN_ERROR_FAILED_GETTING_FUNCTION_ADDRESS;
	}

	diff = (INT_PTR)pNewFunction - ((INT_PTR)iOldFunctionAddr + 5);

	iProtection = VirtualProtect(iOldFunctionAddr, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (0 == iProtection)
	{
		printf("Error in function setHook: Wasn't successful in getting write access to given function. exiting...");
		return RETURN_ERROR_FAILED_IN_GETTING_ACCESS_TO_GIVEN_FUNCTION;
	}

	iOldFunctionAddr[0] = 0xE9;
	memcpy(iOldFunctionAddr + 1, &diff, 4);

	iProtection = VirtualProtect(iOldFunctionAddr, 5, dwOldProtect, &dwOldProtect2);
	if (0 == iProtection)
	{
		printf("Error in function setHook: Wasn't successful in getting the previous to given function. exiting...");
		return RETURN_ERROR_FAILED_IN_RETURNING_ACCESS_TO_GIVEN_FUNCTION;
	}

	return ERROR_SUCCESS;
}

BOOL WINAPI pNewFunction(HANDLE hObject)
{
	printf("HAHA I'm not CloseHandle function and yet you called me!!\n");
	return TRUE;
}