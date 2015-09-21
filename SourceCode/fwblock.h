#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#define  _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <netfw.h>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )


void message(char *mess, char *fbip, DWORD dwProcessId);
int __cdecl fwblock(char *ip);
HRESULT     WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);
BOOL killhim(DWORD dwProcessId);

int __cdecl fwblock(char *ip)
{
	size_t newsize = strlen(ip) + 1;
	OLECHAR * ips = new OLECHAR[strlen(ip) + 1];
	mbstowcs(ips, ip, newsize);
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	INetFwPolicy2 *FwPolicy2 = NULL;
	INetFwRules *FwRules = NULL;
	INetFwRule *FwRule = NULL;


	BSTR RuleName = SysAllocString(L"OUTBOUND_RULE");
	BSTR RuleDescription = SysAllocString(L"Block malicious IP Address");
	BSTR RuleGroup = SysAllocString(L"Malicious Traffic");
	BSTR RemoteIPaddr = SysAllocString(ips);


	// Initialize COM.
	hrComInit = CoInitializeEx(
		0,
		COINIT_APARTMENTTHREADED
		);

	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hrComInit))
		{
			printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
			goto Cleanup;
		}
	}

	// Retrieve INetFwPolicy2
	hr = WFCOMInitialize(&FwPolicy2);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	// Retrieve INetFwRules
	hr = FwPolicy2->get_Rules(&FwRules);
	if (FAILED(hr))
	{
		printf("get_Rules failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&FwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Populate the Firewall Rule object
	FwRule->put_Name(RuleName);
	FwRule->put_Description(RuleDescription);
	FwRule->put_Direction(NET_FW_RULE_DIR_OUT);
	FwRule->put_Grouping(RuleGroup);
	FwRule->put_RemoteAddresses(RemoteIPaddr);
	FwRule->put_Action(NET_FW_ACTION_BLOCK);
	FwRule->put_Enabled(VARIANT_TRUE);

	// Add the Firewall Rule
	hr = FwRules->Add(FwRule);
	if (FAILED(hr))
	{
		printf("Firewall Rule Add failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

Cleanup:
	SysFreeString(RuleName);
	SysFreeString(RuleDescription);
	SysFreeString(RuleGroup);
	SysAllocString(RemoteIPaddr);

	// Release the INetFwRule object
	if (FwRule != NULL)
	{
		FwRule->Release();
	}

	// Release the INetFwRules object
	if (FwRules != NULL)
	{
		FwRules->Release();
	}

	// Release the INetFwPolicy2 object
	if (FwPolicy2 != NULL)
	{
		FwPolicy2->Release();
	}

	// Uninitialize COM.
	if (SUCCEEDED(hrComInit))
	{
		CoUninitialize();
	}

	return 0;


}


// Instantiate INetFwPolicy2
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	HRESULT hr = S_OK;

	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2),
		(void**)ppNetFwPolicy2);

	if (FAILED(hr))
	{
		printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

Cleanup:
	return hr;
}
void message(char * mess, char * fbip,DWORD dwProcessId)
{
	int msgboxID = MessageBox(
		NULL,
		mess,
		"Malicious Activity",
		MB_ICONQUESTION | MB_YESNO);

	switch (msgboxID)
	{
	case IDYES:
		killhim(dwProcessId);
		fwblock(fbip);
		inserts(fbip);
		break;
	case IDNO:
		inserts(fbip);
		break;


	}
}

BOOL killhim(DWORD dwProcessId)
{
	DWORD dwAccess = PROCESS_TERMINATE;
	BOOL  InheritHandle = FALSE;
	HANDLE hProcess = OpenProcess(dwAccess, InheritHandle, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	BOOL result = TerminateProcess(hProcess, 1);

	CloseHandle(hProcess);

	return result;
}
