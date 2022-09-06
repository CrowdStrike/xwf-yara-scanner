///////////////////////////////////////////////////////////////////////////////
// X-Tension API - Function headers
// Copyright X-Ways Software Technology AG
// 
// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation
///////////////////////////////////////////////////////////////////////////////

#ifndef X_Tension__h
#define X_Tension__h

#include <Windows.h>

///////////////////////////////////////////////////////////////////////////////
// Functions that you may call

// XT_RetrieveFunctionPointers - call this function before calling anything else
LONG __stdcall XT_RetrieveFunctionPointers();

// XWF_GetVolumeName (tested)
typedef void(__stdcall* fptr_XWF_GetVolumeName) (HANDLE hVolume, wchar_t* lpString,
	DWORD nType);

// XWF_GetVolumeInformation (tested)
typedef void(__stdcall* fptr_XWF_GetVolumeInformation) (HANDLE hVolume,
	LPLONG lpFileSystem, DWORD* nBytesPerSector, DWORD* nSectorsPerCluster,
	INT64* nClusterCount, INT64* nFirstClusterSectorNo);

// XWF_Read (tested)
typedef DWORD(__stdcall* fptr_XWF_Read) (HANDLE hVolumeOrItem, INT64 nOffset, BYTE* lpBuffer,
	DWORD nNumberOfBytesToRead);

// XWF_GetItemCount
typedef DWORD(__stdcall* fptr_XWF_GetItemCount) (LPVOID pReserved);

// XWF_GetItemName (tested)
typedef const wchar_t* (__stdcall* fptr_XWF_GetItemName) (LONG nItemID);

// XWF_GetItemSize (tested)
typedef INT64(__stdcall* fptr_XWF_GetItemSize) (LONG nItemID);

// XWF_GetItemInformation
typedef INT64(__stdcall* fptr_XWF_GetItemInformation) (LONG nItemID,
	LONG nInfoType, LPBOOL lpSuccess);

// XWF_GetItemParent
typedef LONG(__stdcall* fptr_XWF_GetItemParent) (LONG nItemID);

// XWF_AddToReportTable
typedef LONG(__stdcall* fptr_XWF_AddToReportTable) (LONG nItemID,
	wchar_t* lpReportTableName, DWORD nFlags);

// XWF_GetComment
typedef wchar_t* (__stdcall* fptr_XWF_GetComment) (LONG nItemID);

// XWF_AddComment (tested)
typedef BOOL(__stdcall* fptr_XWF_AddComment) (LONG nItemID, wchar_t* lpComment,
	DWORD nFlagsHowToAdd);

// XWF_OutputMessage (tested)
typedef void(__stdcall* fptr_XWF_OutputMessage) (const wchar_t* lpMessage, DWORD nFlags);

// XWF_ShowProgress
typedef void(__stdcall* fptr_XWF_ShowProgress) (wchar_t* lpCaption, DWORD nFlags);

// XWF_SetProgressPercentage
typedef void(__stdcall* fptr_XWF_SetProgressPercentage) (DWORD nPercent);

// XWF_SetProgressDescription
typedef void(__stdcall* fptr_XWF_SetProgressDescription) (wchar_t* lpStr);

// XWF_ShouldStop
typedef BOOL(__stdcall* fptr_XWF_ShouldStop) (void);

// XWF_GetUserInput
typedef INT64(__stdcall* fptr_XWF_GetUserInput) (LPWSTR lpMessage, LPWSTR lpBuffer,
	DWORD nBufferLen, DWORD nFlags);

// XWF_HideProgress
typedef void(__stdcall* fptr_XWF_HideProgress) (void);

// Open item in a volume
typedef HANDLE(__stdcall* fptr_XWF_OpenItem) (HANDLE hVolume,
	LONG nItemID, DWORD nFlags);

// Close item on a volume
typedef void(__stdcall* fptr_XWF_Close) (HANDLE hVolumeOrItem);

// Retrieve information about the current volume snapshot
typedef INT64(__stdcall* fptr_XWF_GetVSProp) (LONG nPropType, PVOID pBuffer);

// XWF_GetCellText -- added manually by Chris Mayhew
typedef LONG(__stdcall* fptr_XWF_GetCellText) (LONG nItemID,
	LPVOID lpPointer, DWORD nFlags, WORD nColIndex, LPWSTR lpBuffer, DWORD nBufferLen);

// XWF_GetColumnTitle -- added manually by Chris Mayhew
typedef BOOL(__stdcall* fptr_XWF_GetColumnTitle) (WORD nWndNo, WORD nColIndex, LPWSTR lpBuffer);

// XWF_GetHashValue
typedef BOOL(__stdcall* fptr_XWF_GetHashValue) (LONG nItemID, LPVOID lpBuffer);

// XWF_GetProp (tested)
typedef INT64(__stdcall* fptr_XWF_GetProp)(HANDLE hVolumeOrItem, DWORD nPropType, void* lpBuffer);

// XWF_GetEvObjProp
typedef INT64(__stdcall* fptr_XWF_GetEvObjProp) (HANDLE hEvidence, DWORD nPropType,
	PVOID pBuffer);

// XWF_CreateFile
typedef long int(__stdcall* fptr_XWF_CreateFile) (LPWSTR pName, DWORD nCreationFlags,
	LONG nParentItemID, PVOID pSourceInfo);

///////////////////////////////////////////////////////////////////////////////
// Variables that store the function pointers

extern fptr_XWF_GetVolumeName XWF_GetVolumeName;
extern fptr_XWF_GetVolumeInformation XWF_GetVolumeInformation;
extern fptr_XWF_Read XWF_Read;
extern fptr_XWF_GetVSProp XWF_GetVSProp;
extern fptr_XWF_GetItemCount XWF_GetItemCount;
extern fptr_XWF_GetItemName XWF_GetItemName;
extern fptr_XWF_GetItemSize XWF_GetItemSize;
extern fptr_XWF_GetItemInformation XWF_GetItemInformation;
extern fptr_XWF_GetItemParent XWF_GetItemParent;
extern fptr_XWF_AddToReportTable XWF_AddToReportTable;
extern fptr_XWF_GetComment XWF_GetComment;
extern fptr_XWF_AddComment XWF_AddComment;
extern fptr_XWF_OutputMessage XWF_OutputMessage;
extern fptr_XWF_GetUserInput XWF_GetUserInput;
extern fptr_XWF_ShowProgress XWF_ShowProgress;
extern fptr_XWF_SetProgressPercentage XWF_SetProgressPercentage;
extern fptr_XWF_SetProgressDescription XWF_SetProgressDescription;
extern fptr_XWF_ShouldStop XWF_ShouldStop;
extern fptr_XWF_HideProgress XWF_HideProgress;
extern fptr_XWF_GetEvObjProp XWF_GetEvObjProp;
extern fptr_XWF_CreateFile XWF_CreateFile;
extern fptr_XWF_OpenItem XWF_OpenItem;
extern fptr_XWF_Close XWF_Close;
extern fptr_XWF_GetHashValue XWF_GetHashValue;
extern fptr_XWF_GetProp XWF_GetProp;

// Return values from XT_Prepare
constexpr auto XT_PREPARE_STOP_ALL = -4;
constexpr auto XT_PREPARE_STOP_REMAINER = -3;
constexpr auto XT_PREPARE_EXCLUDE_VOLUME = -2;
constexpr auto XT_PREPARE_NO_OTHER_FUNCTIONS = -1;
constexpr auto XT_PREPARE_CALL_FINALIZE = 0;

// Return value flags for XT_PREPARE
constexpr auto XT_PREPARE_CALLPI = 0x01;
constexpr auto XT_PREPARE_CALLPILATE = 0x02;
constexpr auto XT_PREPARE_EXPECTMOREITEMS = 0x04;
constexpr auto XT_PREPARE_DONTOMIT = 0x08;
constexpr auto XT_PREPARE_TARGETDIRS = 0x10;
constexpr auto XT_PREPARE_TARGETZEROBYTEFILES = 0x20;

// XT_Init return values
constexpr auto XT_INIT_ABORT_LOAD = (-1);
constexpr auto XT_INIT_NOT_THREAD_SAFE = 1;
constexpr auto XT_INIT_THREAD_SAFE = 2;

constexpr auto XT_INIT_QUICKCHECK = 0x00000020; // called just to check whether the API accepts the calling application (used by v16.5 and later)
constexpr auto XT_INIT_ABOUTONLY = 0x00000040; // called just to prepare for XT_About (used by v16.5 and later)

constexpr auto XT_ACTION_RUN = 0; // simply run directly from the main menu or command line
constexpr auto XT_ACTION_RVS = 1; // volume snapshot refinement starting
constexpr auto XT_ACTION_DBC = 4; // directory browser context menu command invoked

///////////////////////////////////////////////////////////////////////////////
// Functions that X-Ways Forensics or WinHex may call

struct CallerInfo {
	byte lang, ServiceRelease;
	WORD version;
};

// XT_Init - mandatory export
LONG __stdcall XT_Init(CallerInfo info, DWORD nFlags, HANDLE hMainWnd,
	void* lpReserved);

#endif