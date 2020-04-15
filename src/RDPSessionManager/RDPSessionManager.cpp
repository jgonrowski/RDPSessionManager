// RDPSessionManager.cpp : Defines the entry point for the application.
//

#include "pch.h"
#include "framework.h"
#include "md5.h"
#include "RDPSessionManager.h"

using json = nlohmann::json;

struct SessionInfo {
	LPWSTR UserName;
	LPWSTR SessionName;
	std::wstring SessionState;
	DWORD SessionID;
};

HINSTANCE appInstance;
HANDLE serverHandle;
PWTS_SESSION_INFO_1 info;
std::vector<SessionInfo> sessions;
std::wstring address;
DWORD sessionId;
wchar_t sessionIdData[MAX_PATH];
wchar_t sessionStateData[MAX_PATH];
STARTUPINFO cif = { 0 };
PROCESS_INFORMATION pi = { 0 };

wchar_t historyFile[MAX_PATH];

std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

INT_PTR CALLBACK ServerPromptDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK MainDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
json settings;

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	INITCOMMONCONTROLSEX params;
	params.dwICC = ICC_WIN95_CLASSES;
	params.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCommonControlsEx(&params);
	
	appInstance = hInstance;

	BOOL ok = SHGetSpecialFolderPath(NULL, historyFile, CSIDL_COMMON_APPDATA, TRUE);
	PathAppend(historyFile, L"RDPSessionManager.settings");

	return DialogBox(hInstance, MAKEINTRESOURCE(IDD_PREFERENCES), NULL, ServerPromptDialogProc);
}

void LoadCredentials(HWND dlg) {
	PCREDENTIALW creds;
	HWND serverAddressInput = GetDlgItem(dlg, IDC_SERVER_ADDRESS);
	wchar_t addressStr[MAX_PATH];
	GetWindowText(serverAddressInput, addressStr, MAX_PATH);
	HWND credentialsInput = GetDlgItem(dlg, IDC_EDIT_CREDENTIALS);
	if (CredRead(addressStr, CRED_TYPE_DOMAIN_PASSWORD, 0, &creds)) {		
		SetWindowText(credentialsInput, creds->UserName);
	}
	else {
		SetWindowText(credentialsInput, L"");
	}
}

void LoadHistory(HWND serverListDialog) {
	if (settings["last_connected"].is_string()) {
		HWND serverAddressInput = GetDlgItem(serverListDialog, IDC_SERVER_ADDRESS);
		std::wstring serverAddress = converter.from_bytes(settings["last_connected"].get<std::string>());
		SetWindowText(serverAddressInput, serverAddress.c_str());
		LoadCredentials(serverListDialog);
	}
	if (settings["no_consent_prompt"].is_number_unsigned()) {
		CheckDlgButton(serverListDialog, IDC_PREFERENCES_NOPROMPT, settings["no_consent_prompt"].get<UINT>());
	}
}

void LoadSettings() {
	std::ifstream settingsFile(historyFile);
	if (settingsFile.good()) {
		settingsFile >> settings;
	}
}

void SaveHistory(HWND serverListDialog) {
	HWND serverAddressInput = GetDlgItem(serverListDialog, IDC_SERVER_ADDRESS);
	wchar_t addressStr[MAX_PATH];
	GetWindowText(serverAddressInput, addressStr, MAX_PATH);
	address = addressStr;
	UINT checked = IsDlgButtonChecked(serverListDialog, IDC_PREFERENCES_NOPROMPT);
	settings["last_connected"] = converter.to_bytes(address);
	settings["no_consent_prompt"] = checked;
	std::ofstream settingsFile(historyFile);
	settingsFile << settings;
}

void PromptCredentials(HWND serverListDialog) {
	CREDUI_INFO creduiInfo = { 
		sizeof(CREDUI_INFO), 
		NULL, 
		L"Enter username and password", 
		L"Server Admin Credentials",
		NULL
	};
	DWORD authError = 0;
	ULONG authPackage = 0;
	LPVOID authBuffer = NULL;
	ULONG authBufferSize = 0;
	BOOL authSave = false;
	DWORD res = CredUIPromptForWindowsCredentials(&creduiInfo, authError, &authPackage, NULL, 0, &authBuffer, &authBufferSize, &authSave, CREDUIWIN_GENERIC | CREDUIWIN_PACK_32_WOW);
	if (res == ERROR_SUCCESS)
	{
		DWORD maxUserNameSize = CREDUI_MAX_USERNAME_LENGTH;
		DWORD maxDomainNameSize = CREDUI_MAX_DOMAIN_TARGET_LENGTH;
		DWORD maxPasswordLength = CREDUI_MAX_PASSWORD_LENGTH;

		LPWSTR szUserName = new WCHAR[maxUserNameSize];
		LPWSTR szDomain = new WCHAR[maxDomainNameSize];
		LPWSTR szPassword = new WCHAR[maxPasswordLength];

		DWORD dwCredBufferSize = authBufferSize;

		DWORD lastError = 0;
		res = CredUnPackAuthenticationBuffer(
			CRED_PACK_GENERIC_CREDENTIALS,
			authBuffer,
			dwCredBufferSize,
			szUserName,
			&maxUserNameSize,
			szDomain,
			&maxDomainNameSize,
			szPassword,
			&maxPasswordLength
		);
		lastError = GetLastError();

		if (res == FALSE)
		{
			MessageBox(NULL, L"Blah", L"CredUnPackAuthenticationBuffer", MB_OK);
		}
		else
		{			
			size_t blobsize = wcslen(szPassword);

			CREDENTIAL cred = { 0 };
			wchar_t addressStr[MAX_PATH];
			HWND serverAddressInput = GetDlgItem(serverListDialog, IDC_SERVER_ADDRESS);
			GetWindowText(serverAddressInput, addressStr, MAX_PATH);
			address = addressStr;
			wchar_t target[MAX_PATH];
			wsprintf(target, L"%s", address.c_str());
			cred.Flags = 0;
			cred.Type = CRED_TYPE_DOMAIN_PASSWORD;
			cred.TargetName = target;
			cred.CredentialBlobSize = blobsize * sizeof(wchar_t);
			cred.CredentialBlob = (LPBYTE)szPassword;
			cred.Persist = CRED_PERSIST_ENTERPRISE;
			cred.UserName = szUserName;
			int res = CredWrite(&cred, 0);
			if (!res) {
				DWORD err = GetLastError();
				wchar_t errText[MAX_PATH];
				wsprintf(errText, L"Err %d", err);
				MessageBox(NULL, errText, L"", MB_OK);
			}
			else {
				HWND credentialsInput = GetDlgItem(serverListDialog, IDC_EDIT_CREDENTIALS);
				SetWindowText(credentialsInput, szUserName);
			}
		}

	}

	SecureZeroMemory(authBuffer, authBufferSize);
	CoTaskMemFree(authBuffer);
}

void ClearCredentials(HWND serverListDialog) {
	std::wstring serverAddress = converter.from_bytes(settings["last_connected"].get<std::string>());
	if (CredDelete(serverAddress.c_str(), CRED_TYPE_DOMAIN_PASSWORD, 0)) {
		HWND credentialsInput = GetDlgItem(serverListDialog, IDC_EDIT_CREDENTIALS);
		SetWindowText(credentialsInput, L"");
	}
}

bool init(HWND dlg) {
	if (settings["last_connected"].is_string()) {
		address = converter.from_bytes(settings["last_connected"].get<std::string>().c_str());
		serverHandle = WTSOpenServerEx((LPWSTR)address.c_str());
		WTSRegisterSessionNotificationEx(serverHandle, dlg, NOTIFY_FOR_ALL_SESSIONS);
		return true;
	}
	else {
		return false;
	}
}

void SetupListView(HWND dlg) {
	HWND listview = GetDlgItem(dlg, IDC_SESSIONS_LIST);
	ListView_SetExtendedListViewStyle(listview, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	LVCOLUMN listCol = { 0 };
	listCol.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	listCol.pszText = (LPWSTR)L"User";
	listCol.cx = 200;
	SendMessage(listview, LVM_INSERTCOLUMN, 0, (LPARAM)&listCol);
	listCol.cx = 150;
	listCol.pszText = (LPWSTR)L"Session ID";
	SendMessage(listview, LVM_INSERTCOLUMN, 1, (LPARAM)&listCol);
	listCol.pszText = (LPWSTR)L"Session name";
	SendMessage(listview, LVM_INSERTCOLUMN, 2, (LPARAM)&listCol);
	listCol.pszText = (LPWSTR)L"State";
	SendMessage(listview, LVM_INSERTCOLUMN, 3, (LPARAM)&listCol);
}

std::wstring StateToString(WTS_CONNECTSTATE_CLASS state) {
	switch (state) {
	case WTSActive:
		return L"Active";
	case WTSConnected:
		return L"Connected";
	case WTSConnectQuery:
		return L"Connecting";
	case WTSShadow:
		return L"Shadowing";
	case WTSDisconnected:
		return L"Disconnected";
	case WTSIdle:
		return L"Idle";
	case WTSListen:
		return L"Listen";
	case WTSReset:
		return L"Reset";
	case WTSDown:
		return L"Down";
	case WTSInit:
		return L"Initializing";
	}
	return L"Unknown";
}

void RefreshSessions(HWND dlg) {
	DWORD level = 1;
	DWORD count;
	WTSEnumerateSessionsEx(serverHandle, &level, 0, &info, &count);
	HWND listview = GetDlgItem(dlg, IDC_SESSIONS_LIST);
	ListView_DeleteAllItems(listview);

	LVITEM lvI = { 0 };

	lvI.pszText = LPSTR_TEXTCALLBACK;
	lvI.mask = LVIF_TEXT;
	lvI.iItem = 0;
	lvI.iSubItem = 0;

	sessions.clear();

	for (size_t i = 0; i < count; i++) {
		WTS_SESSION_INFO_1* item = (WTS_SESSION_INFO_1*)&info[i];
		if (item->pUserName) {
			SessionInfo session = { item->pUserName, item->pSessionName, StateToString(item->State), item->SessionId };
			sessions.push_back(session);
		}
	}

	for (size_t i = 0; i < sessions.size(); i++) {

		lvI.iItem = i;

		int res = ListView_InsertItem(listview, &lvI);
	}
}

void ConnectTo(DWORD sessionId, bool control) {
	std::wstringstream mstscCommandLine;
	mstscCommandLine << "mstsc /v:" << address << " /shadow:" << sessionId;
	if (settings["no_consent_prompt"].is_number_unsigned() && settings["no_consent_prompt"].get<UINT>() > 0) {
		mstscCommandLine << " /noConsentPrompt";
	}
	else {
		mstscCommandLine << " /prompt";
	}
	if (control) {
		mstscCommandLine << " /control";
	}
	OutputDebugString(mstscCommandLine.str().c_str());
	CreateProcess(NULL, (LPWSTR)mstscCommandLine.str().c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &cif, &pi);
}

void ConnectSelected(HWND dlg, bool control) {
	HWND listview = GetDlgItem(dlg, IDC_SESSIONS_LIST);
	int iPos = ListView_GetNextItem(listview, -1, LVNI_SELECTED);
	while (iPos != -1) {
		SessionInfo session = sessions[iPos];
		ConnectTo(session.SessionID, control);
		iPos = ListView_GetNextItem(listview, iPos, LVNI_SELECTED);
	}
}

void LogoffSelected(HWND dlg) {
	HWND listview = GetDlgItem(dlg, IDC_SESSIONS_LIST);
	int iPos = ListView_GetNextItem(listview, -1, LVNI_SELECTED);
	while (iPos != -1) {
		SessionInfo session = sessions[iPos];
		WTSLogoffSession(serverHandle, session.SessionID, TRUE);
		iPos = ListView_GetNextItem(listview, iPos, LVNI_SELECTED);
	}
}

void HandleWM_NOTIFY(HWND hwnd, LPARAM lParam)
{
	NMLVDISPINFO* plvdi;
	LPNMITEMACTIVATE lpnmitem;
	DWORD sessionId;

	switch (((LPNMHDR)lParam)->code)
	{
	case LVN_GETDISPINFO:

		plvdi = (NMLVDISPINFO*)lParam;

		switch (plvdi->item.iSubItem)
		{
		case 0:
			plvdi->item.pszText = sessions[plvdi->item.iItem].UserName;
			break;
		case 1:
			sessionId = sessions[plvdi->item.iItem].SessionID;
			wsprintf(sessionIdData, L"#%d", sessionId);
			plvdi->item.pszText = sessionIdData;
			break;
		case 2:
			plvdi->item.pszText = sessions[plvdi->item.iItem].SessionName;
			break;
		case 3:
			wsprintf(sessionStateData, L"%s", sessions[plvdi->item.iItem].SessionState.c_str());
			plvdi->item.pszText = sessionStateData;
			break;
		default:
			break;
		}

		break;
	case NM_DBLCLK:
		lpnmitem = (LPNMITEMACTIVATE)lParam;
		sessionId = sessions[lpnmitem->iItem].SessionID;
		ConnectTo(sessionId, false);
		break;
	case NM_RCLICK:
		POINT cursor;
		GetCursorPos(&cursor);
		HMENU contextMenu = (HMENU)GetSubMenu(LoadMenu(appInstance, MAKEINTRESOURCE(IDC_RDPSESSIONMANAGER)), 0);
		SetMenuDefaultItem(contextMenu, 0, TRUE);
		TrackPopupMenu(contextMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, hwnd, NULL);
		break;
	}
	return;
}

BOOL ValidateInfodict(HWND dlg) {
	HWND infodictHwnd = GetDlgItem(dlg, IDC_STATIC_INFODICT);
	wchar_t infodict[MAX_PATH];
	GetWindowText(infodictHwnd, infodict, MAX_PATH);
	char ch[260];
	char DefChar = ' ';
	WideCharToMultiByte(CP_ACP, 0, infodict, -1, ch, 260, &DefChar, NULL);
	std::string infodictTxt(ch);
	std::string md5_infodict = md5(infodictTxt);
	std::regex re("(.{2}[^7][7])(.{4}[^0][0])(.{5}[^3][3])(.{7}[^f][f])(.{4}[^4][4])");
	std::smatch pieces;
	if (!std::regex_match(md5_infodict, pieces, re)) {
		EndDialog(dlg, 0);
		return FALSE;
	}
	return TRUE;
}

void SetElementTextFont(HWND dlg) {
	HFONT hFont = CreateFontW(-12, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
	SendDlgItemMessage(dlg, IDC_STATIC_INFODICT, WM_SETFONT, (WPARAM)(hFont), TRUE);
}

BOOL SetElementTextColor(HWND dlg, WPARAM wParam, LPARAM lParam) {
	HDC hdc = (HDC)wParam;
	SetBkColor(hdc, RGB(240, 240, 240));
	if (IDC_STATIC_INFODICT == ::GetDlgCtrlID((HWND)lParam))
	{
		SetTextColor(hdc, RGB(171, 171, 171));
	}
	return (BOOL)CreateSolidBrush(RGB(240, 240, 240));
}

INT_PTR CALLBACK ServerPromptDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
		SetElementTextFont(hwnd);
		LoadHistory(hwnd);
		return TRUE;
	case WM_CTLCOLORSTATIC:
		return SetElementTextColor(hwnd, wParam, lParam);
		break;
	case WM_COMMAND:
		if (((HWND)lParam) && (HIWORD(wParam) == BN_CLICKED))
		{
			int iMID;
			iMID = LOWORD(wParam);
			switch (iMID)
			{
			case IDC_BUTTON_PROMPT_CREDENTIALS:
				PromptCredentials(hwnd);
				break;
			case IDC_BUTTON_CLEAR_CREDENTIALS:
				ClearCredentials(hwnd);
				break;
			case IDC_VIEW:
			{
				SaveHistory(hwnd);
				EndDialog(hwnd, 1);
				break;
			}
			default:
				break;
			}
		}
		if (((HWND)lParam) && (HIWORD(wParam) == EN_KILLFOCUS))
		{
			LoadCredentials(hwnd);
		}
		return TRUE;
	case WM_WINDOWPOSCHANGING:
		return ValidateInfodict(hwnd);
	case WM_CLOSE:
		EndDialog(hwnd, 0);
		return FALSE;
	default:
		return FALSE;
	}

}

INT_PTR CALLBACK MainDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
	HMENU preferencesMenu;
	INT_PTR preferencesResult;
	switch (message)
	{
	case WM_INITDIALOG:
		LoadSettings();
		SetupListView(hwnd);
		preferencesMenu = LoadMenu(appInstance, MAKEINTRESOURCE(IDR_MAINMENU));
		SetMenu(hwnd, preferencesMenu);
		init(hwnd);
		RefreshSessions(hwnd);
		return TRUE;
	case  WM_WTSSESSION_CHANGE:
		RefreshSessions(hwnd);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDM_RDPSESSIONMANAGER_VIEW:
			ConnectSelected(hwnd, false);
			break;
		case IDM_RDPSESSIONMANAGER_CONTROL:
			ConnectSelected(hwnd, true);
			break;

		case IDM_RDPSESSIONMANAGER_LOGOFF:
			LogoffSelected(hwnd);
			break;
		case ID_FILE_PREFERENCES:
			preferencesResult = DialogBox(appInstance, MAKEINTRESOURCE(IDD_PREFERENCES), NULL, ServerPromptDialogProc);
			if (preferencesResult == 1) {
				init(hwnd);
				RefreshSessions(hwnd);
			}
			break;
		case ID_FILE_EXIT:
			EndDialog(hwnd, 0);
			break;

		default:
			break;

		}
		return TRUE;
	case WM_NOTIFY:
		HandleWM_NOTIFY(hwnd, lParam);
		return TRUE;
	case WM_CLOSE:
		EndDialog(hwnd, 0);
		return FALSE;

	default:
		return FALSE;
	}
}