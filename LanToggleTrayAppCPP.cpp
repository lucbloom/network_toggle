#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <commctrl.h>
#include <strsafe.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <wbemidl.h>
#include <comdef.h>
#include <oleauto.h>

#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Resource IDs
#define IDM_EXIT 201
#define IDM_TOGGLE 202
#define WM_TRAYICON (WM_USER + 1)


// Global variables
HINSTANCE g_hInstance = NULL;
HWND g_hWnd = NULL;
NOTIFYICONDATA g_nid = { 0 };
std::wstring g_adapterName;
bool g_adapterEnabled = true;
HICON g_hOnIcon = NULL;
HICON g_hOffIcon = NULL;

// Function prototypes
std::wstring GetFirstLanAdapterName();
void ToggleAdapter();

// Window procedure
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_TRAYICON:
		switch (LOWORD(lParam)) {
		case WM_LBUTTONDBLCLK:
			ToggleAdapter();
			break;
		case WM_RBUTTONUP:
		case WM_CONTEXTMENU: {
			POINT pt;
			GetCursorPos(&pt);
			HMENU hMenu = CreatePopupMenu();
			if (hMenu) {
				InsertMenu(hMenu, -1, MF_BYPOSITION | MF_STRING, IDM_TOGGLE,
					(std::wstring(L"Toggle ") + (g_adapterEnabled ? L"OFF" : L"ON")).c_str());
				InsertMenu(hMenu, -1, MF_BYPOSITION | MF_STRING, IDM_EXIT, L"Exit");

				// Required to make menu work with keyboard
				SetForegroundWindow(hWnd);

				// Show the menu
				TrackPopupMenu(hMenu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_LEFTBUTTON,
					pt.x, pt.y, 0, hWnd, NULL);

				DestroyMenu(hMenu);
			}
			break;
		}
		}
		return 0;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		case IDM_TOGGLE:
			ToggleAdapter();
			break;
		}
		return 0;

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}

	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

// Entry point
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	g_hInstance = hInstance;

	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &adminGroup)) {
		if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
			isAdmin = FALSE;
		}
		FreeSid(adminGroup);
	}

	// Check for admin privileges
	if (isAdmin != TRUE) {
#ifndef _DEBUG
		wchar_t szPath[MAX_PATH];
		if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
			SHELLEXECUTEINFO sei = { sizeof(sei) };
			sei.lpVerb = L"runas";
			sei.lpFile = szPath;
			sei.hwnd = NULL;
			sei.nShow = SW_NORMAL;

			if (ShellExecuteEx(&sei)) {
				// Process will restart with elevation
				return 0;
			}
		}

		MessageBox(NULL, L"Failed to restart with administrator privileges.", L"Network Toggler", MB_OK | MB_ICONERROR);
		return 1;
#endif
	}

	// Get the first LAN adapter name
	g_adapterName = GetFirstLanAdapterName();
	if (g_adapterName.empty()) {
		g_adapterName = L"Ethernet";
	}

	// Initialize common controls
	INITCOMMONCONTROLSEX icex = { 0 };
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	::InitCommonControlsEx(&icex);

	// Load icons
	g_hOnIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON_ON));
	g_hOffIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON_OFF));

	if (!g_hOnIcon || !g_hOffIcon) {
		MessageBox(NULL, L"Failed to load icons.", L"Network Toggler", MB_OK | MB_ICONERROR);
		return 1;
	}

	// Register window class
	const wchar_t CLASS_NAME[] = L"NetworkToggler";

	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = CLASS_NAME;
	wc.hIcon = g_hOffIcon;

	RegisterClass(&wc);

	// Create the hidden window
	g_hWnd = CreateWindowEx(
		0, // Optional window styles
		CLASS_NAME, // Window class
		L"Network Toggler", // Window title
		WS_OVERLAPPEDWINDOW, // Window style
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, // Parent window	
		NULL, // Menu
		hInstance, // Instance handle
		NULL // Additional data
	);

	if (g_hWnd == NULL) {
		MessageBox(NULL, L"Window Creation Failed!", L"Error", MB_OK | MB_ICONERROR);
		return 1;
	}

	// Check if adapter is enabled
	g_adapterEnabled = true; // Assume enabled by default

	// Add the icon to the system tray
	ZeroMemory(&g_nid, sizeof(g_nid));
	g_nid.cbSize = sizeof(NOTIFYICONDATA);
	g_nid.hWnd = g_hWnd;
	g_nid.uID = 1;
	g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	g_nid.uCallbackMessage = WM_TRAYICON;
	g_nid.hIcon = g_adapterEnabled ? g_hOnIcon : g_hOffIcon;

	StringCchCopy(g_nid.szTip, ARRAYSIZE(g_nid.szTip),
		(L"Network Adapter: " + g_adapterName + (g_adapterEnabled ? L" (ON)" : L" (OFF)")).c_str());

	Shell_NotifyIcon(NIM_ADD, &g_nid);

	// Main message loop
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	// Cleanup before exit
	Shell_NotifyIcon(NIM_DELETE, &g_nid);

	return (int)msg.wParam;
}

// Get the first LAN adapter name with connection name (not description)
// Get the first LAN adapter name with connection name
std::wstring GetFirstLanAdapterName() {
	std::wstring adapterName = L"Ethernet"; // Default fallback name

	// Initialize COM
	HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		return adapterName;
	}

	// Initialize COM security
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
		CoUninitialize();
		return adapterName;
	}

	// Create WMI instance
	IWbemLocator* pLoc = NULL;
	hr = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&pLoc
	);

	if (FAILED(hr)) {
		CoUninitialize();
		return adapterName;
	}

	// Connect to WMI
	IWbemServices* pSvc = NULL;
	hr = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pSvc
	);

	if (FAILED(hr)) {
		pLoc->Release();
		CoUninitialize();
		return adapterName;
	}

	// Set security levels
	hr = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hr)) {
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return adapterName;
	}

	// Create WMI query
	IEnumWbemClassObject* pEnumerator = NULL;
	hr = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionStatus = 2 AND AdapterTypeId = 0"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hr)) {
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return adapterName;
	}

	// Get the first network adapter
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	if (pEnumerator) {
		hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (SUCCEEDED(hr) && uReturn == 1) {
			VARIANT vtProp;
			VariantInit(&vtProp);

			// Get the NetConnectionID property
			hr = pclsObj->Get(L"NetConnectionID", 0, &vtProp, 0, 0);
			if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
				adapterName = vtProp.bstrVal;
				VariantClear(&vtProp);
			}

			pclsObj->Release();
		}

		pEnumerator->Release();
	}

	// Clean up
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return adapterName;
}

std::wstring GetFirstLanAdapterNamePowerShell() {
	// Use WMI to get the connection name that netsh uses
	std::wstring adapterName = L"Ethernet"; // Default name

	// Temporary file for PowerShell output
	wchar_t tempPath[MAX_PATH];
	wchar_t tempFileName[MAX_PATH];

	GetTempPath(MAX_PATH, tempPath);
	GetTempFileName(tempPath, L"net", 0, tempFileName);

	// PowerShell command to get the network connection name
	std::wstring psCommand = L"powershell -Command \"Get-NetAdapter | Where-Object {$_.MediaType -eq 'Ethernet' -and $_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name\" > \"";
	psCommand += tempFileName;
	psCommand += L"\"";

	// Execute the PowerShell command
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	wchar_t* cmd = new wchar_t[psCommand.length() + 1];
	wcscpy_s(cmd, psCommand.length() + 1, psCommand.c_str());

	if (CreateProcess(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, 10000); // Wait up to 10 seconds
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		// Read the result from the temp file
		HANDLE hFile = CreateFile(tempFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD fileSize = GetFileSize(hFile, NULL);
			if (fileSize > 0 && fileSize != INVALID_FILE_SIZE) {
				std::vector<wchar_t> buffer(fileSize / 2 + 1, 0);
				DWORD bytesRead;

				if (ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
					// Convert to wstring and trim whitespace
					std::wstring result(buffer.data());
					size_t start = result.find_first_not_of(L" \t\r\n");
					size_t end = result.find_last_not_of(L" \t\r\n");

					if (start != std::wstring::npos && end != std::wstring::npos) {
						adapterName = result.substr(start, end - start + 1);
					}
				}
			}
			CloseHandle(hFile);
		}

		// Delete the temp file
		DeleteFile(tempFileName);
	}

	delete[] cmd;

	// If no adapter found with PowerShell, try WMI as fallback
	if (adapterName == L"Ethernet") {
		// Try another method using WMI
		psCommand = L"powershell -Command \"(Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {$_.NetConnectionStatus -eq 2} | Select-Object -First 1 -ExpandProperty NetConnectionID)\" > \"";
		psCommand += tempFileName;
		psCommand += L"\"";

		cmd = new wchar_t[psCommand.length() + 1];
		wcscpy_s(cmd, psCommand.length() + 1, psCommand.c_str());

		if (CreateProcess(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
			WaitForSingleObject(pi.hProcess, 10000); // Wait up to 10 seconds
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			// Read the result from the temp file
			HANDLE hFile = CreateFile(tempFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				DWORD fileSize = GetFileSize(hFile, NULL);
				if (fileSize > 0 && fileSize != INVALID_FILE_SIZE) {
					std::vector<wchar_t> buffer(fileSize / 2 + 1, 0);
					DWORD bytesRead;

					if (ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
						// Convert to wstring and trim whitespace
						std::wstring result(buffer.data());
						size_t start = result.find_first_not_of(L" \t\r\n");
						size_t end = result.find_last_not_of(L" \t\r\n");

						if (start != std::wstring::npos && end != std::wstring::npos) {
							adapterName = result.substr(start, end - start + 1);
						}
					}
				}
				CloseHandle(hFile);
			}

			// Delete the temp file
			DeleteFile(tempFileName);
		}

		delete[] cmd;
	}

	return adapterName;
}

// Toggle the adapter state
void ToggleAdapter() {
	g_adapterEnabled = !g_adapterEnabled;

	std::wstring command = L"netsh interface set interface \"" + g_adapterName + L"\" " +
		(g_adapterEnabled ? L"enabled" : L"disabled");

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	// Create a writeable copy of the command
	wchar_t* cmd = new wchar_t[command.length() + 1];
	wcscpy_s(cmd, command.length() + 1, command.c_str());

	bool result = CreateProcess(NULL, cmd, NULL, NULL, FALSE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	delete[] cmd;

	if (result) {
		// Wait for the process to finish
		WaitForSingleObject(pi.hProcess, INFINITE);

		// Get the exit code
		DWORD exitCode;
		GetExitCodeProcess(pi.hProcess, &exitCode);

		// Close process handles
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		result = exitCode == 0;
	}

	if (result) {
		g_nid.hIcon = g_adapterEnabled ? g_hOnIcon : g_hOffIcon;
		StringCchCopy(g_nid.szTip, ARRAYSIZE(g_nid.szTip),
			(L"Network Adapter: " + g_adapterName + (g_adapterEnabled ? L" (ON)" : L" (OFF)")).c_str());
		Shell_NotifyIcon(NIM_MODIFY, &g_nid);
	}
	else {
		// Revert the state if it failed
		g_adapterEnabled = !g_adapterEnabled;
		MessageBox(g_hWnd, L"Failed to toggle network adapter state.", L"Network Toggler", MB_OK | MB_ICONERROR);
	}
}
