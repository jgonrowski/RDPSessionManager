#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <commctrl.h>
#include <wtsapi32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wincred.h>
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <locale>
#include <codecvt>
#include <regex>

#include "json.hpp"
