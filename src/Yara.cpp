///////////////////////////////////////////////////////////////////////////////
// YARA Scanner X-Tension Version 1.0
// Based on YARA 4.1.0 API
// Written by Chris Mayhew - CrowdStrike
// Thank you to the team at CrowdStrike for helping to build and troubleshoot
// Copyright 2021 CrowdStrike, Inc.
///////////////////////////////////////////////////////////////////////////////
#include "X-Tension.h"
#include <yara.h>
#include <string>

// Return values from XT_Prepare
#define XT_PREPARE_STOP_ALL (-4)
#define XT_PREPARE_STOP_REMAINER (-3)
#define XT_PREPARE_EXCLUDE_VOLUME (-2)
#define XT_PREPARE_NO_OTHER_FUNCTIONS (-1)
#define XT_PREPARE_CALL_FINALIZE (0)

// Return value flags for XT_PREPARE
#define XT_PREPARE_CALLPI (1)

// XT_Init return values
#define XT_INIT_ABORT_LOAD (-1)
#define XT_INIT_NOT_THREAD_SAFE (1)
#define XT_INIT_THREAD_SAFE (2)

// Define the file path size for user input
constexpr size_t gYaraRulePathSize = 300;

YR_COMPILER* gYaraCompiler;
YR_RULES* gYaraRules;
YR_SCANNER* gYaraScanner;
INT64 gYaraWarnings = 0;
INT64 g_nOpTypeBackup = 0;
INT64 gUserFileSize = 0;
INT64 gBufferSize = 100000000; // 100MB
time_t gProcessingBegin;

// To convert strings to wstrings
std::wstring string2wstring (
	const std::string& str
	)
{
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

// This is called on successful YARA rule match
int YaraScanCallback ( 
	YR_SCAN_CONTEXT* context,
	int message,
	void* message_data,
	void* user_data
	)
{
	// (LONG)user_data is the nItemID passed into YaraScanCallback()
	INT64 nitemID = (INT64)user_data;

	// this gets called when the yara scan has finished
	if (message == CALLBACK_MSG_SCAN_FINISHED)
	{
		return CALLBACK_ABORT;
	}
	// this gets called when the yara scan has rule match
	else if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		// Gets the YARA rule that matched the file
		YR_RULE* rule = (YR_RULE*)message_data;
		// check there is content in the rule match, if not then the scan is finished
		if (rule == nullptr)
		{
			return CALLBACK_ABORT;
		}
		std::wstring identifier = L"[YARA] " + string2wstring(rule->identifier);

		if (XWF_AddToReportTable(nitemID, L"YARA Hits", 0) == 0)
		{
			XWF_OutputMessage(L"Unable to add YARA hit to report table - no case is active", 0);
			return CALLBACK_ABORT;
		}

		if (XWF_AddComment(nitemID, (wchar_t*)identifier.c_str(), 2) == FALSE)
		{
			XWF_OutputMessage(L"Unable to add comment to file", 0);
			return CALLBACK_ABORT;
		}
		return CALLBACK_CONTINUE;
	}
	return CALLBACK_CONTINUE;
}

void YaraCompileCallback (
	int nErrorLevel,
	const char* szFileNameA,
	int nLineNumber,
	const YR_RULE* pRule,
	const char* szErrorMessageA,
	void* pUserData
	)
{
	std::wstring warning = L"error";
	// replace warning different string if it's at the different warning level
	if (nErrorLevel == YARA_ERROR_LEVEL_WARNING)
	{
		warning = L"warning";
		gYaraWarnings++;
	}
	else if (nErrorLevel == YARA_ERROR_LEVEL_ERROR)
	{
		// Create the error string
		std::wstring Yara_Error = L"YARA " + warning +
			L" in file " + string2wstring(szFileNameA) +
			L" | line " + std::to_wstring(nLineNumber) +
			L": " + string2wstring(szErrorMessageA);
		XWF_OutputMessage(Yara_Error.c_str(), 0);
	}
}

// XT_Init() will be called before anything else happens
LONG 
XT_Init (
	DWORD nVersion,
	DWORD nFlags,
	HANDLE hMainWnd,
	void* lpReserved
	)
{
	XT_RetrieveFunctionPointers();
	return XT_INIT_THREAD_SAFE;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About() will be called when the user requests to see information about the DLL.
LONG
XT_About (
	HANDLE hParentWnd,
	void* lpReserved
	)
{
	XWF_OutputMessage(L"YARA X-Tension V1.0 written by Chris Mayhew - CrowdStrike", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare will be called immediately for a volume when volume snapshot refinement
// or some other action starts
LONG
XT_Prepare (
	HANDLE hVolume,
	HANDLE hEvidence,
	DWORD nOpType,
	void* lpReserved
	)
{
	// save the mode in which the X-Tension is called
	g_nOpTypeBackup = nOpType;

	// Initialize YARA library
	if (yr_initialize() != ERROR_SUCCESS)
	{
		XWF_OutputMessage(L"Failed to initialise YARA library", 0);
		return XT_PREPARE_CALL_FINALIZE;
	}
	XWF_OutputMessage(L"YARA library initialised", 0);

	// Load YARA rules from file first
	LPWSTR user_input = new WCHAR[gYaraRulePathSize];
	swprintf(user_input, gYaraRulePathSize, L"%s", L"yararules.txt");

	if (XWF_GetUserInput(L"Enter location of YARA rules file", user_input, gYaraRulePathSize, 0) == -1)
	{
		// -1 returned if user clicks cancel on the input window
		delete[] user_input;
		return XT_PREPARE_STOP_ALL;
	}

	FILE* fl;
	if (_wfopen_s(&fl, user_input, L"r") != 0)
	{
		XWF_OutputMessage(L"YARA rule file empty or not found - exiting", 0);
		delete[] user_input;
		return XT_PREPARE_STOP_ALL;
	}

	// we need to save the user input as a char for the function yr_compiler_add_file()
	char yara_rule_file_char[gYaraRulePathSize];
	std::wcstombs(yara_rule_file_char, user_input, gYaraRulePathSize);
	delete[] user_input;

	if (g_nOpTypeBackup == XT_ACTION_RVS)
	{
		gUserFileSize = XWF_GetUserInput(L"[RVS] Enter maximum file size to scan (in MB).", 0, 0, 1);
		// -1 returned if user clicks cancel on the input window
		if (gUserFileSize == -1)
		{
			return XT_PREPARE_STOP_ALL;
		}
		// convert to bytes
		gUserFileSize = gUserFileSize * 1000000;

		// if the user selects a max file size of more than 100, ask for the chunk size
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
	else if (g_nOpTypeBackup == XT_ACTION_DBC)
	{
		// Ask for the chunk size regarless in DBC mode
		gBufferSize = XWF_GetUserInput(L"[DBC] Enter scan buffer size (in MB).", 0, 0, 1);
		if (gBufferSize == -1)
		{
			return XT_PREPARE_STOP_ALL;
		}
		gBufferSize = gBufferSize * 1000000;
	}

	// Create a YARA compiler
	if (yr_compiler_create(&gYaraCompiler) != ERROR_SUCCESS)
	{
		XWF_OutputMessage(L"Failed to create YARA compiler", 0);
		gYaraCompiler = nullptr;
		return XT_PREPARE_CALL_FINALIZE;
	}

	// Set compiler callback function
	yr_compiler_set_callback(gYaraCompiler, YaraCompileCallback, nullptr);

	// Compile the YARA rules from the rule file yara_rule_file_char
	if (yr_compiler_add_file(gYaraCompiler, fl, nullptr, yara_rule_file_char) != ERROR_SUCCESS)
	{
		XWF_OutputMessage(L"YARA was unable to compile the provided rules", 0);
		yr_compiler_destroy(gYaraCompiler);
		if (fl != nullptr)
		{
			fclose(fl);
		}
		yr_finalize();
		return XT_PREPARE_STOP_ALL;
	}
	// close the rules file 
	if (fl != nullptr)
	{
		fclose(fl);
	}

	if (gYaraWarnings > 0)
	{
		std::wstring warnings_yara = L"There were " + std::to_wstring(gYaraWarnings) + 
			L" YARA compile warnings. Check these against the stand alone YARA v4.1.0 binary";
		XWF_OutputMessage(warnings_yara.c_str(), 0);
	}

	// Get the compiled rules from the compiler
	if (yr_compiler_get_rules(gYaraCompiler, &gYaraRules) != ERROR_SUCCESS)
	{
		XWF_OutputMessage(L"Failed to load the compiled rules - exiting", 0);
		yr_compiler_destroy(gYaraCompiler);
		return XT_PREPARE_CALL_FINALIZE;
	}

	// Creates a new scanner that can be used for scanning data with the provided rules.
	if (yr_scanner_create(gYaraRules, &gYaraScanner) != ERROR_SUCCESS)
	{
		XWF_OutputMessage(L"Failed to create YARA scanner", 0);
		yr_compiler_destroy(gYaraCompiler);
		gYaraScanner = nullptr;
		return XT_PREPARE_CALL_FINALIZE;
	}
	// Destroy the compiler as we no longer need it
	else
	{
		yr_compiler_destroy(gYaraCompiler);
	}

	XWF_OutputMessage(L"YARA rules compiled successfully", 0);

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
LONG
XT_Finalize (
	HANDLE hVolume,
	HANDLE hEvidence,
	DWORD nOpType,
	void* lpReserved
	)
{
	// show the time taken
	if (g_nOpTypeBackup == XT_ACTION_DBC)
	{
		XWF_HideProgress();
		time_t ProcessingEnd;
		time(&ProcessingEnd);
		std::wstring time_taken = L"Operation Complete. Processing time: " + std::to_wstring(difftime(ProcessingEnd, gProcessingBegin)) + L"s";
		XWF_OutputMessage(time_taken.c_str(), 0);
	}

	// Finalise YARA library
	if (yr_finalize() != ERROR_SUCCESS)
	{
		XWF_OutputMessage(L"Failed to finalise YARA library", 0);
	}
	XWF_OutputMessage(L"YARA library finalised", 0);

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItemEx() will be called for each item in the volume snapshot that is targeted for refinement
LONG
XT_ProcessItemEx (
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
	INT64 FileSize = XWF_GetProp(hItem, 1, nullptr);
	
	// if running via RVS - skip files more than UserFileSize
	if (g_nOpTypeBackup == XT_ACTION_RVS && FileSize > gUserFileSize)
	{
		return 0;
	}
	std::wstring FileName = XWF_GetItemName(nItemID);

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
			std::wstring XwfReadError = L"Error reading the contents of " + FileName +
				L" into memory. Export file and scan with standlone YARA binary";
			XWF_OutputMessage(XwfReadError.c_str(), 0);
		}

		// Only report on matching rules (SCAN_FLAGS_REPORT_RULES_MATCHING)
		// Calls YaraScanCallback() on each successful match
		// Passes the nItemID to the user_data parameter so that we can update the metadata within XWF for that file
		int nResult = yr_rules_scan_mem(gYaraRules, FileBuffer, BufferSize, SCAN_FLAGS_REPORT_RULES_MATCHING, YaraScanCallback, (void*)nItemID, 0);

		// check for errors from yr_rules_scan_mem()
		if (nResult != ERROR_SUCCESS)
		{
			if (XWF_AddToReportTable(nItemID, L"Yara Errors", 0) == 0)
			{
				XWF_OutputMessage(L"Unable to add YARA error to report table - no case is active", 0);
			}

			YR_RULE* yara_error_rule = yr_scanner_last_error_rule(gYaraScanner);
			std::wstring error = L"Error - file " + FileName + L" not scanned. Error " + std::to_wstring(nResult);
			if (yara_error_rule != nullptr)
			{
				std::wstring error = L"Error - file " +
					FileName + L" not scanned. Error " +
					std::to_wstring(nResult) + L" | YARA rule: " +
					string2wstring(yara_error_rule->identifier);
			}
			XWF_OutputMessage(error.c_str(), 0);
		}
	}
	// delete buffer now it has been used
	delete[] FileBuffer;

	// return 0 for XT_ProcessItemEx()
	return 0;
}
