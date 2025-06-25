///////////////////////////////////////////////////////////////////////////////
// YARA Scanner X-Tension Version 1.4
// Based on YARA 4.5.0 API
// Written by Chris Mayhew & Joe Duin - CrowdStrike
// Thank you to the team at CrowdStrike for helping to build and troubleshoot
// Copyright 2025 CrowdStrike, Inc.
///////////////////////////////////////////////////////////////////////////////
#include "X-Tension.h"
#include <yara.h>
#include <string>
#include <tchar.h>
#include <algorithm>
#include <vector>
#include <iterator>

using namespace std;
YR_COMPILER* gYaraCompiler;
YR_RULES* gYaraRules;
YR_SCANNER* gYaraScanner;
bool gCompiledYaraMode = false;
bool gAbortTrue = false;
bool gCliMode = false;
HWND gWindowHandle;
INT64 gYaraWarnings = 0;
INT64 gYaraHitCount = 0;
INT64 gYaraDupCount = 0;
INT64 g_nOpTypeBackup = 0;
INT64 g_nOpTypeBackup_init = 0;
INT64 gUserFileSize = 0;
INT64 gBufferSize = 100000000; // 100MB
time_t gProcessingBegin;
LPWSTR gUserInput = new WCHAR[MAX_PATH * 10];
char yara_rule_file_char[MAX_PATH + 1];
wchar_t* YR_VERSION_w = new wchar_t[strlen(YR_VERSION) + 1];

// Check for substring in comment
bool isDupComment(const wstring& s1, const wstring& s2) noexcept
{
	if (s1.find(s2) != string::npos)
	{
		return true;
	}
	return false;
}

// Test if string ends with substring
bool ends_with(const wstring& s, const wstring& suffix)
{
	if (suffix.length() > s.length())
	{
		return false;
	}

	auto s_iterator = s.rbegin(), suffix_iterator = suffix.rbegin();
	while (suffix_iterator != suffix.rend())
	{
		if (*s_iterator != *suffix_iterator)
		{
			return false;
		}
		s_iterator++;
		suffix_iterator++;
	}
	return true;
}

// Take yara file paths from the command line TODO: XWF profile for RVS
vector<wstring> parseCommandLine(const LPWSTR& cmdInput)
{
	auto cmdLine = wstring(cmdInput);
	auto fullPaths = vector<wstring>();
	auto paramStart = cmdLine.find(L"\"XTParam:yararule:");
	auto hasQuotes = true;

	if (paramStart == string::npos)
	{
		paramStart = cmdLine.find(L"XTParam:yararule:");
		if (paramStart == string::npos)
		{
			return fullPaths;
		}
		hasQuotes = false;
	}
	else
	{
		paramStart++;
	}
	paramStart += 17;

	auto searchChar = hasQuotes ? L'\"' : L' ';
	auto yaraFile = cmdLine.substr(paramStart, cmdLine.find(searchChar, paramStart) - paramStart);
	if (yaraFile.length())
	{
		fullPaths.push_back(yaraFile);
	}

	return fullPaths; // TODO: Add support for multiple files
}

// Converts filepicker path to a vector of strings containing full paths
vector<wstring> parsePaths(const LPWSTR& s)
{
	vector<wstring> paths;
	for (auto i = 0u, len = 0u; len = wcslen(&s[i]); i += len + 1)
	{
		paths.push_back(&s[i]);
	}

	if (paths.size() > 1)
	{
		for (auto i = paths.begin() + 1; i != paths.end(); ++i)
		{
			*i = *paths.begin() + L"\\" + *i;
		}
		paths.erase(paths.begin());
	}
	return paths;
}

// This is called on successful YARA rule match
int YaraScanCallback(
	YR_SCAN_CONTEXT* context,
	int message,
	void* message_data,
	void* user_data
)
{
	// user_data is the nItemID passed into YaraScanCallback()
	INT64 nItemID = (INT64)user_data;

	// this gets called when the yara scan has finished
	if (message == CALLBACK_MSG_SCAN_FINISHED)
	{
		return CALLBACK_ABORT;
	}
	// this gets called when the yara scan has rule match
	else if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		// Gets the YARA rule that matched the file
		const YR_RULE* rule = (YR_RULE*)message_data;
		// check there is content in the rule match, if not then the scan is finished
		if (rule == nullptr)
		{
			return CALLBACK_ABORT;
		}
		gYaraHitCount++;
		string id = rule->identifier;
		wstring identifier = wstring(id.begin(), id.end()).c_str();
		identifier = L"[YARA] " + identifier;

		const wchar_t* itemComment = XWF_GetComment(nItemID); // TODO: Who is responsible for freeing this?
		if (itemComment == NULL || !isDupComment(wstring(itemComment), identifier))
		{
			if (XWF_AddToReportTable(nItemID, L"YARA Hits", 0) == 0)
			{
				XWF_OutputMessage(L"Unable to add YARA hit to report table - no case is active", 0);
				return CALLBACK_ABORT;
			}

			if (XWF_AddComment(nItemID, (wchar_t*)identifier.c_str(), 2) == FALSE)
			{
				XWF_OutputMessage(L"Unable to add comment to file", 0);
				return CALLBACK_ABORT;
			}
		}
		else
		{
			gYaraDupCount++;
		}
		return CALLBACK_CONTINUE;
	}
	return CALLBACK_CONTINUE;
}

void YaraCompileCallback(
	int nErrorLevel,
	const char* szFileNameA,
	int nLineNumber,
	const YR_RULE* pRule,
	const char* szErrorMessageA,
	void* pUserData
)
{
	// Set errors to log to console and warnings to case log
	wstring warning = L"warning";
	int outputFlag = 16;
	if (nErrorLevel == YARA_ERROR_LEVEL_ERROR)
	{
		warning = L"error";
		outputFlag = 0;
	}
	else
	{
		gYaraWarnings++;
	}

	// Create the error string
	string fileName = szFileNameA;
	string errorMessage = szErrorMessageA;
	wstring fileNameW = wstring(fileName.begin(), fileName.end()).c_str();
	wstring errorMessageW = wstring(errorMessage.begin(), errorMessage.end()).c_str();
	wstring Yara_Error = L"YARA " + warning + L" in file " + fileNameW
		+ L" | line " + to_wstring(nLineNumber) + L": " + errorMessageW;
	XWF_OutputMessage(Yara_Error.c_str(), outputFlag);
}

// XT_Init() will be called before anything else happens
LONG
XT_Init(
	DWORD nVersion,
	DWORD nFlags,
	HANDLE hMainWnd,
	void* lpReserved
)
{
	XT_RetrieveFunctionPointers();

	g_nOpTypeBackup_init = nFlags;
	gWindowHandle = static_cast<HWND>(hMainWnd);

	// save YARA version
	mbstowcs_s(NULL, YR_VERSION_w, strlen(YR_VERSION) + 1, YR_VERSION, strlen(YR_VERSION));

	// Don't do anything else if XWF is doing a quick check
	if (g_nOpTypeBackup_init != XT_INIT_QUICKCHECK)
	{
		// Initialize YARA library
		auto yrInitSuccess = yr_initialize();
		if (yrInitSuccess != ERROR_SUCCESS)
		{
			auto yrInitMsg = L"Failed to initialise YARA library. Error code: " + to_wstring(yrInitSuccess);
			XWF_OutputMessage(yrInitMsg.c_str(), 0);
			delete[] gUserInput;
			return XT_INIT_ABORT_LOAD;
		}

		wstring result(YR_VERSION_w);
		auto yara_version = L"YARA " + result + L" library initialised";
		XWF_OutputMessage(yara_version.c_str(), 1);

		// Get YARA file path from command line, if specified (only one file supported for now)
		LPWSTR cmdInput = GetCommandLineW();
		auto fullPaths = parseCommandLine(cmdInput);
		if (fullPaths.size())
		{
			gCliMode = true;
		}

		if (!gCliMode) {
			// Filepicker to select a YARA file
			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = static_cast<HWND>(hMainWnd);
			ofn.lpstrFilter = _T("Text Files\0*.txt\0YARA Files\0*.yara;*.yar\0Any File\0*.*\0\0");
			ofn.lpstrFile = gUserInput;
			ofn.lpstrFile[0] = '\0';
			ofn.nMaxFile = MAX_PATH * 10;
			ofn.lpstrTitle = _T("Select YARA rules file");
			ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST | OFN_EXPLORER | OFN_ALLOWMULTISELECT;
			if (!GetOpenFileName(&ofn))
			{
				// clean exit if cancelled
				gAbortTrue = true;
				delete[] gUserInput;
				return XT_INIT_THREAD_SAFE;
			}
			fullPaths = parsePaths(gUserInput);
			if (!fullPaths.size())
			{
				XWF_OutputMessage(L"Files not found", 0);
				delete[] gUserInput;
				return XT_INIT_ABORT_LOAD;
			}
		}
		else
		{
			XWF_OutputMessage(L"YARA path selected from command line: ", 0);
			XWF_OutputMessage(fullPaths[0].c_str(), 0);
		}
		delete[] gUserInput;

		// Set YARA mode
		if (ends_with(fullPaths[0], L".yara") || ends_with(fullPaths[0], L".yar"))
		{
			if (fullPaths.size() > 1)
			{
				XWF_OutputMessage(L"Only one compiled YARA file can be specified at this time", 0);
				return XT_INIT_ABORT_LOAD;
			}
			gCompiledYaraMode = true;
		}
		else
		{
			for (auto i = fullPaths.begin(); i != fullPaths.end(); ++i)
			{
				if (!ends_with(*i, L".txt"))
				{
					XWF_OutputMessage(L"Inappropriate combination of file types", 0);
					return XT_INIT_ABORT_LOAD;
				}
			}
		}

		if (!gCompiledYaraMode)
		{
			// Create a YARA compiler
			if (yr_compiler_create(&gYaraCompiler) != ERROR_SUCCESS)
			{
				XWF_OutputMessage(L"Failed to create YARA compiler", 0);
				gYaraCompiler = nullptr;
				return XT_INIT_ABORT_LOAD;
			}

			// Set compiler callback function
			yr_compiler_set_callback(gYaraCompiler, YaraCompileCallback, nullptr);
		}

		for (auto i = 0u; i < fullPaths.size(); ++i)
		{
			// we need to save the user input as a char for the function yr_compiler_add_file()
			if (fullPaths[i].length() <= MAX_PATH)
			{
				wcstombs(yara_rule_file_char, fullPaths[i].c_str(), MAX_PATH);
			}
			else
			{
				XWF_OutputMessage(L"YARA rule file path exceeds max path length - exiting", 0);
				return XT_INIT_ABORT_LOAD;
			}

			// Skip compiler for compiled YARA
			if (gCompiledYaraMode)
			{
				auto yrLoadSuccess = yr_rules_load(yara_rule_file_char, &gYaraRules);
				if (yrLoadSuccess == ERROR_UNSUPPORTED_FILE_VERSION)
				{
					XWF_OutputMessage(L"The YARA version used to compile the rules in your chosen file is incompatible with version:", 0);
					XWF_OutputMessage(YR_VERSION_w, 1);
					yr_finalize();
					return XT_INIT_ABORT_LOAD;
				}
				else if (yrLoadSuccess != ERROR_SUCCESS)
				{
					auto yrLoadMsg = L"YARA was unable to use the supplied compiled rules file. Error code: " + to_wstring(yrLoadSuccess);
					XWF_OutputMessage(yrLoadMsg.c_str(), 0);
					yr_finalize();
					return XT_INIT_ABORT_LOAD;
				}
				break;
			}

			// Compile the YARA rules from the rule file yara_rule_file_char
			FILE* fl;
			if (_wfopen_s(&fl, fullPaths[i].c_str(), L"r") != 0)
			{
				XWF_OutputMessage(L"YARA rule file empty or not found - exiting", 0);
				return XT_INIT_ABORT_LOAD;
			}

			if (yr_compiler_add_file(gYaraCompiler, fl, nullptr, yara_rule_file_char) != ERROR_SUCCESS)
			{
				wstring compilerErrMsgBox = L"YARA was unable to compile the provided rules";
				XWF_OutputMessage(compilerErrMsgBox.c_str(), 0);
				yr_compiler_destroy(gYaraCompiler);
				if (fl != nullptr)
				{
					fclose(fl);
				}
				gAbortTrue = true;
				if (!gCliMode)
				{
					MessageBox(
						gWindowHandle,
						compilerErrMsgBox.c_str(),
						L"YARA X-Tension error",
						MB_ICONSTOP | MB_OK
					);
				}
				return XT_INIT_THREAD_SAFE;
			}
			// close the rules file
			if (fl != nullptr)
			{
				fclose(fl);
			}
		}

		if (!gCompiledYaraMode)
		{
			if (gYaraWarnings > 0)
			{
				wstring warnings_yara = L"There were " + to_wstring(gYaraWarnings) +
					L" YARA compile warnings. Check the XWF case log for details";
				XWF_OutputMessage(warnings_yara.c_str(), 0);
			}

			// Get the compiled rules from the compiler
			if (yr_compiler_get_rules(gYaraCompiler, &gYaraRules) != ERROR_SUCCESS)
			{
				XWF_OutputMessage(L"Failed to load the compiled rules - exiting", 0);
				yr_compiler_destroy(gYaraCompiler);
				return XT_INIT_ABORT_LOAD;
			}
		}

		// Creates a new scanner that can be used for scanning data with the provided rules.
		if (yr_scanner_create(gYaraRules, &gYaraScanner) != ERROR_SUCCESS)
		{
			XWF_OutputMessage(L"Failed to create YARA scanner", 0);
			if (!gCompiledYaraMode)
			{
				yr_compiler_destroy(gYaraCompiler);
			}
			gYaraScanner = nullptr;
			return XT_INIT_ABORT_LOAD;
		}
		// Destroy the compiler as we no longer need it
		else if (!gCompiledYaraMode)
		{
			yr_compiler_destroy(gYaraCompiler);
		}

		wstring yrRuleAddSuccess = gCompiledYaraMode ? L" added " : L" compiled ";
		wstring yrRuleAddMsg = L"YARA rules" + yrRuleAddSuccess + L"successfully";
		XWF_OutputMessage(yrRuleAddMsg.c_str(), 0);
	}

	return XT_INIT_THREAD_SAFE;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About() will be called when the user requests to see information about the DLL.
LONG
XT_About(
	HANDLE hParentWnd,
	void* lpReserved
) noexcept
{
	wstring result(YR_VERSION_w);
	auto yara_version = L"YARA X-Tension V1.4 written by Chris Mayhew & Joe Duin - CrowdStrike. Based on YARA " + result;
	XWF_OutputMessage(yara_version.c_str(), 1);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare will be called immediately for a volume when volume snapshot refinement
// or some other action starts
LONG
XT_Prepare(
	HANDLE hVolume,
	HANDLE hEvidence,
	DWORD nOpType,
	void* lpReserved
) noexcept
{
	// abort if filepicker cancelled or XT_INIT error
	if (gAbortTrue)
	{
		return XT_PREPARE_STOP_ALL;
	}

	// save the mode in which the X-Tension is called
	g_nOpTypeBackup = nOpType;

	if (g_nOpTypeBackup == XT_ACTION_RVS && gUserFileSize == 0)
	{
		gUserFileSize = XWF_GetUserInput(L"[RVS] Enter maximum file size to scan (in MB).", 0, 0, 1);
		// -1 returned if user clicks cancel on the input window
		if (gUserFileSize == -1)
		{
			return XT_PREPARE_STOP_ALL;
		}
		// convert to bytes
		gUserFileSize = gUserFileSize * 1000000;

		// if the user selects a max file size of more than 100MB, ask for the chunk size
		if (gUserFileSize > 100000000)
		{
			gBufferSize = XWF_GetUserInput(L"[RVS] Enter scan buffer size (in MB).", 0, 0, 1);
			if (gBufferSize == -1)
			{
				return XT_PREPARE_STOP_ALL;
			}
			gBufferSize = gBufferSize * 1000000;
		}
	}
	else if (g_nOpTypeBackup == XT_ACTION_DBC && gBufferSize == 0)
	{
		// Ask for the chunk size regardless in DBC mode
		gBufferSize = XWF_GetUserInput(L"[DBC] Enter scan buffer size (in MB).", 0, 0, 1);
		if (gBufferSize == -1)
		{
			return XT_PREPARE_STOP_ALL;
		}
		gBufferSize = gBufferSize * 1000000;
	}
	else if (g_nOpTypeBackup == XT_ACTION_RUN)
	{
		wstring modeErrMsgBox = L"X-Tension mode not supported: Please run from Refine Volume Snapshot or file context menu.";
		XWF_OutputMessage(modeErrMsgBox.c_str(), 0);
		if (!gCliMode)
		{
			MessageBox(
				gWindowHandle,
				modeErrMsgBox.c_str(),
				L"YARA X-Tension error",
				MB_ICONSTOP | MB_OK
			);
		}
		return XT_PREPARE_STOP_ALL;
	}

	// Bring up the progress bar if the user runs from context menu
	if (g_nOpTypeBackup == XT_ACTION_DBC)
	{
		XWF_ShowProgress(L"Running YARA...", 1);
		time(&gProcessingBegin);
	}
	return XT_PREPARE_CALLPI;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Finalize
// Will be called when volume snapshot refinement or another operation has completed. 
LONG
XT_Finalize(
	HANDLE hVolume,
	HANDLE hEvidence,
	DWORD nOpType,
	void* lpReserved
)
{
	// show the time taken and summary
	if (g_nOpTypeBackup == XT_ACTION_DBC)
	{
		XWF_HideProgress();
		time_t ProcessingEnd;
		time(&ProcessingEnd);
		wstring time_taken = L"Operation Complete. Processing time: " + to_wstring(difftime(ProcessingEnd, gProcessingBegin)) + L"s";
		XWF_OutputMessage(time_taken.c_str(), 0);
	}

	// Sumary of hits and duplicates
	wstring dupPlural = gYaraDupCount == 1 ? L"duplicate" : L"duplicates";
	wstring dupInfo = gYaraDupCount > 0 ? L" (" + to_wstring(gYaraDupCount) + L" " + dupPlural + L")" : L"";
	wstring hitPlural = gYaraHitCount == 1 ? L"hit" : L"hits";
	wstring hitInfo = L"";
	if (gYaraHitCount != 0 && gYaraHitCount - gYaraDupCount > 0)
	{
		hitInfo = L", files with hits have been added to the \"YARA Hits\" label (report table). The rule that matched has been added as a comment.";
	}
	wstring hitSummary = L"Summary: Found " + to_wstring(gYaraHitCount) + L" YARA " + hitPlural + dupInfo + hitInfo;
	XWF_OutputMessage(hitSummary.c_str(), 0);

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done
// Will be called just before the DLL is unloaded
LONG
XT_Done(
	void* lpReserved
) noexcept
{
	if (g_nOpTypeBackup_init < XT_INIT_QUICKCHECK)
	{
		// Finalise YARA library
		auto yrFinSuccess = yr_finalize();
		if (yrFinSuccess != ERROR_SUCCESS)
		{
			auto yrFinMsg = L"Failed to finalise YARA library. Error code: " + to_wstring(yrFinSuccess);
			XWF_OutputMessage(yrFinMsg.c_str(), 0);
		}
		else
		{
			XWF_OutputMessage(L"YARA library finalised", 0);
		}
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItemEx() will be called for each item in the volume snapshot that is targeted for refinement
LONG
XT_ProcessItemEx(
	INT64 nItemID,
	HANDLE hItem,
	void* lpReserved
)
{
	// grab the set BufferSize from the global variable to save as local
	INT64 BufferSize = gBufferSize;

	// allow the user to cancel if lengthy operation
	XWF_ShouldStop();

	// Get logical file size first and later create the buffer to load the file into
	const INT64 FileSize = XWF_GetProp(hItem, 1, nullptr);

	// if running via RVS - skip files more than UserFileSize
	if (g_nOpTypeBackup == XT_ACTION_RVS && FileSize > gUserFileSize)
	{
		return 0;
	}
	wstring FileName = XWF_GetItemName(nItemID);

	// check to see if the X-Tension is running via DBC menu
	if (g_nOpTypeBackup == XT_ACTION_DBC)
	{
		XWF_SetProgressDescription((wchar_t*)XWF_GetItemName(nItemID));
	}

	// Don't allocate more than file size if not needed.
	if (FileSize < BufferSize)
	{
		BufferSize = FileSize;
	}
	BYTE* FileBuffer = new BYTE[BufferSize];

	// keep going until we have reached all parts of the buffer
	for (INT64 Offset = 0; Offset < FileSize; Offset += BufferSize)
	{
		// adjust on final loop, so not to read over what is available
		if (Offset + BufferSize > FileSize)
		{
			BufferSize = FileSize - Offset;
		}

		// we need to read the file passed by XT_ProcessItemEx() in a memory buffer, in chunks
		if (XWF_Read(hItem, Offset, FileBuffer, BufferSize) != BufferSize)
		{
			wstring XwfReadError = L"Error reading the contents of " + FileName +
				L" into memory. Export file and scan with standalone YARA binary";
			XWF_OutputMessage(XwfReadError.c_str(), 0);
		}

		// Only report on matching rules (SCAN_FLAGS_REPORT_RULES_MATCHING)
		// Calls YaraScanCallback() on each successful match
		// Passes the nItemID to the user_data parameter so that we can update the metadata within XWF for that file
		const int nResult = yr_rules_scan_mem(gYaraRules, FileBuffer, BufferSize, SCAN_FLAGS_REPORT_RULES_MATCHING,
			YaraScanCallback, (void*)nItemID, 0);

		// check for errors from yr_rules_scan_mem()
		if (nResult != ERROR_SUCCESS)
		{
			if (XWF_AddToReportTable(nItemID, L"YARA Errors", 0) == 0)
			{
				XWF_OutputMessage(L"Unable to add YARA error to report table - no case is active", 0);
			}

			const YR_RULE* yara_error_rule = yr_scanner_last_error_rule(gYaraScanner);
			wstring error = L"Error - file " + FileName + L" not scanned. Error " + to_wstring(nResult);
			if (yara_error_rule != nullptr)
			{
				string id = yara_error_rule->identifier;
				error = L"Error - file " + FileName + L" not scanned. Error " + to_wstring(nResult) + L" | YARA rule: " + wstring(id.begin(), id.end()).c_str();
			}
			XWF_OutputMessage(error.c_str(), 0);
		}
	}
	// delete buffer now it has been used
	delete[] FileBuffer;

	// return 0 for XT_ProcessItemEx()
	return 0;
}
