///////////////////////////////////////////////////////////////////////////////
// X-Tension API - Function headers
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#ifndef X_Tension__h
#define X_Tension__h

#include <Windows.h>

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

///////////////////////////////////////////////////////////////////////////////
// Functions that you may call

// XT_RetrieveFunctionPointers - call this function before calling anything else
LONG __stdcall XT_RetrieveFunctionPointers();

// XWF_GetSize (tested, deprecated, use XWF_GetProp instead)
typedef INT64 (__stdcall *fptr_XWF_GetSize) (HANDLE hVolumeOrItem, LPVOID lpOptional);

// XWF_GetVolumeName (tested)
typedef void (__stdcall *fptr_XWF_GetVolumeName) (HANDLE hVolume, wchar_t* lpString, 
	DWORD nType);

// XWF_GetVolumeInformation (tested)
typedef void (__stdcall *fptr_XWF_GetVolumeInformation) (HANDLE hVolume, 
	LPLONG lpFileSystem, DWORD* nBytesPerSector, DWORD* nSectorsPerCluster, 
	INT64* nClusterCount, INT64* nFirstClusterSectorNo);

// XWF_GetSectorContents
typedef BOOL (__stdcall *fptr_XWF_GetSectorContents) (HANDLE hVolume, INT64 nSectorNo, 
	wchar_t* lpDescr, LPLONG lpItemID);

// XWF_Read (tested)
typedef DWORD (__stdcall *fptr_XWF_Read) (HANDLE hVolumeOrItem, INT64 nOffset, BYTE* lpBuffer, 
	DWORD nNumberOfBytesToRead);

// XWF_SectorIO
typedef DWORD(__stdcall *fptr_XWF_SectorIO) (LONG nDrive, INT64 nSector, DWORD nCount,
	LPVOID lpBuffer, LPDWORD nFlags);

// XWF_SelectVolumeSnapshot
typedef void (__stdcall *fptr_XWF_SelectVolumeSnapshot) (HANDLE hVolume);

// XWF_GetItemCount
typedef DWORD (__stdcall *fptr_XWF_GetItemCount) (LPVOID pReserved);

// XWF_GetFileCount
typedef DWORD(__stdcall *fptr_XWF_GetFileCount) (LONG nDirID);

// XWF_CreateItem
typedef long int (__stdcall *fptr_XWF_CreateItem) (wchar_t* lpName, DWORD nCreationFlags);

#pragma pack(2) 
struct SrcInfo {
	DWORD nStructSize;
	INT64 nBufSize;
	LPVOID pBuffer;
};

// XWF_CreateFile
typedef long int(__stdcall *fptr_XWF_CreateFile) (LPWSTR pName, DWORD nCreationFlags,
	LONG nParentItemID,	PVOID pSourceInfo);

// XWF_FindItem1
typedef long int(__stdcall *fptr_XWF_FindItem1) (LONG nParentItemID, LPWSTR lpName,
	DWORD nFlags, LONG nSearchStartItemID);

// XWF_GetItemName (tested)
typedef const wchar_t* (__stdcall *fptr_XWF_GetItemName) (LONG nItemID);

// XWF_GetItemSize (tested)
typedef INT64 (__stdcall *fptr_XWF_GetItemSize) (LONG nItemID); 

// XWF_SetItemSize
typedef void (__stdcall *fptr_XWF_SetItemSize) (LONG nItemID, INT64 nSize); 

// XWF_GetItemOfs
typedef void (__stdcall *fptr_XWF_GetItemOfs) (LONG nItemID, INT64* lpDefOfs, 
	INT64* lpStartSector); 

// XWF_SetItemOfs
typedef void (__stdcall *fptr_XWF_SetItemOfs) (LONG nItemID, INT64 nDefOfs, 
	INT64 nStartSector); 

// XWF_GetItemInformation
typedef INT64 (__stdcall *fptr_XWF_GetItemInformation) (LONG nItemID, 
   LONG nInfoType, LPBOOL lpSuccess); 

// XWF_SetItemInformation
typedef BOOL (__stdcall *fptr_XWF_SetItemInformation) (LONG nItemID, 
   LONG nInfoType, INT64 nInfoValue);

// XWF_GetItemType
typedef LONG (__stdcall *fptr_XWF_GetItemType) (LONG nItemID, wchar_t*lpTypeDescr, 
	DWORD nBufferLenAndFlags);

// XWF_SetItemType
typedef void (__stdcall *fptr_XWF_SetItemType) (LONG nItemID, wchar_t*lpTypeDescr, 
	LONG nTypeStatus); 

// XWF_GetItemParent
typedef LONG (__stdcall *fptr_XWF_GetItemParent) (LONG nItemID); 

// XWF_SetItemParent
typedef void (__stdcall *fptr_XWF_SetItemParent) (LONG nChildItemID, LONG nParentItemID); 

// XWF_GetHashSetAssocs
typedef LONG (__stdcall *fptr_XWF_GetHashSetAssocs) (LONG nItemID, LPWSTR lpBuffer,
	LONG nBufferLen);

// XWF_GetReportTableAssocs
typedef LONG (__stdcall *fptr_XWF_GetReportTableAssocs) (LONG nItemID, 
	wchar_t* lpBuffer, LONG nBufferLen); 

// XWF_AddToReportTable
typedef LONG (__stdcall *fptr_XWF_AddToReportTable) (LONG nItemID, 
	wchar_t* lpReportTableName, DWORD nFlags); 

// XWF_GetComment
typedef wchar_t* (__stdcall *fptr_XWF_GetComment) (LONG nItemID); 

// XWF_AddComment (tested)
typedef BOOL (__stdcall *fptr_XWF_AddComment) (LONG nItemID, wchar_t* lpComment, 
	DWORD nFlagsHowToAdd);

// XWF_OutputMessage (tested)
typedef void (__stdcall * fptr_XWF_OutputMessage) (const wchar_t* lpMessage, DWORD nFlags); 

// XWF_GetUserInput
typedef INT64(__stdcall * fptr_XWF_GetUserInput) (LPWSTR lpMessage, LPWSTR lpBuffer,
	DWORD nBufferLen, DWORD nFlags);

// XWF_ShowProgress
typedef void (__stdcall * fptr_XWF_ShowProgress) (wchar_t* lpCaption, DWORD nFlags);   

// XWF_SetProgressPercentage
typedef void (__stdcall * fptr_XWF_SetProgressPercentage) (DWORD nPercent); 

// XWF_SetProgressDescription
typedef void (__stdcall * fptr_XWF_SetProgressDescription) (wchar_t* lpStr); 

// XWF_ShouldStop
typedef BOOL (__stdcall * fptr_XWF_ShouldStop) (void); 

// XWF_HideProgress
typedef void (__stdcall * fptr_XWF_HideProgress) (void); 

// XWF_ReleaseMem
typedef BOOL(__stdcall * fptr_XWF_ReleaseMem) (PVOID lpBuffer);

// Open item in a volume
typedef HANDLE (__stdcall * fptr_XWF_OpenItem) (HANDLE hVolume,
   LONG nItemID, DWORD nFlags);

// Close item on a volume
typedef void (__stdcall * fptr_XWF_Close) (HANDLE hVolumeOrItem);

// Create evidence object
typedef HANDLE (__stdcall * fptr_XWF_CreateEvObj) (DWORD nType, LONG nDiskID,
   LPWSTR lpPath, PVOID pReserved);

// Retrieve information about the current volume snapshot
typedef INT64 (__stdcall * fptr_XWF_GetVSProp) (LONG nPropType, PVOID pBuffer);

#pragma pack(2)
struct SearchInfo {
   LONG iSize;
   HANDLE hVolume;
   LPWSTR lpSearchTerms;
   DWORD nFlags;
   DWORD nSearchWindow;
};

#pragma pack(2)
struct CodePages {
   LONG iSize;
   WORD nCodePage1;
   WORD nCodePage2;
   WORD nCodePage3;
   WORD nCodePage4;
   WORD nCodePage5;
};

// XWF_Search
typedef LONG(__stdcall * fptr_XWF_Search) (SearchInfo* SInfo, CodePages* CPages);

// XWF_AddSearchTerm
typedef LONG(__stdcall * fptr_XWF_AddSearchTerm) (LPWSTR lpSearchTermName, DWORD nFlags);

// XWF_GetSearchTerm
typedef LPWSTR(__stdcall * fptr_XWF_GetSearchTerm) (LONG nSearchTermID, LPVOID pReserved);

// XWF_CreateContainer
typedef HANDLE (__stdcall * fptr_XWF_CreateContainer) (LPWSTR lpFileName, 
   DWORD nFlags, LPVOID pReserved);

// XWF_CopyToContainer
typedef LONG (__stdcall * fptr_XWF_CopyToContainer) (HANDLE hContainer, 
   HANDLE hItem, DWORD nFlags, DWORD nMode, INT64 nStartOfs, 
   INT64 nEndOfs, LPVOID pReserved);

// XWF_CloseContainer
typedef LONG (__stdcall * fptr_XWF_CloseContainer) (HANDLE hContainer, 
   LPVOID pReserved);

// XWF_GetBlock
typedef BOOL (__stdcall * fptr_XWF_GetBlock) (HANDLE hVolume, INT64* lpStartOfs, INT64* lpEndOfs);

// XWF_SetBlock
typedef BOOL (__stdcall * fptr_XWF_SetBlock) (HANDLE hVolume, INT64 nStartOfs, INT64 nEndOfs);

// XWF_GetCaseProp
typedef INT64 (__stdcall * fptr_XWF_GetCaseProp) (LPVOID pReserved, LONG nPropType, PVOID pBuffer,
   LONG nBufLen);

// XWF_GetFirstEvObj
typedef HANDLE (__stdcall * fptr_XWF_GetFirstEvObj) (LPVOID pReserved);

// XWF_GetNextEvObj
typedef HANDLE (__stdcall * fptr_XWF_GetNextEvObj) (HANDLE hPrevEvidence, LPVOID pReserved);

// XWF_OpenEvObj
typedef HANDLE (__stdcall * fptr_XWF_OpenEvObj) (HANDLE hEvidence, DWORD nFlags);

// XWF_CloseEvObj
typedef VOID (__stdcall * fptr_XWF_CloseEvObj) (HANDLE hEvidence);

// XWF_GetEvObj
typedef HANDLE (__stdcall * fptr_XWF_GetEvObj) (DWORD nEvObjID);

// XWF_GetEvObjProp
typedef INT64 (__stdcall * fptr_XWF_GetEvObjProp) (HANDLE hEvidence, DWORD nPropType,
   PVOID pBuffer);

// XWF_GetExtractedMetadata
typedef LPWSTR (__stdcall * fptr_XWF_GetExtractedMetadata) (LONG nItemID);

// XWF_GetMetadataEx
typedef LPVOID (__stdcall * fptr_XWF_GetMetadataEx) (HANDLE hItem, PDWORD lpnFlags);

// XWF_GetRasterImage
typedef LPVOID(__stdcall * fptr_XWF_GetRasterImage) (struct RasterImageInfo* RIInfo);

// XWF_AddExtractedMetadata
typedef BOOL (__stdcall * fptr_XWF_AddExtractedMetadata) (LONG nItemID, LPWSTR lpComment, DWORD nFlagsHowToAdd);

// XWF_GetHashValue
typedef BOOL (__stdcall * fptr_XWF_GetHashValue) (LONG nItemID, LPVOID lpBuffer);

// XWF_SetHashValue
typedef BOOL (__stdcall * fptr_XWF_SetHashValue) (LONG nItemID, LPVOID lpHash, DWORD nParam);

#pragma pack(2)
struct EventInfo {
   LONG iSize;
   HANDLE hEvidence;
   DWORD nEvtType;
   DWORD nFlags;
   FILETIME TimeStamp;
   LONG nItemID;
   INT64 nOfs;
   LPSTR lpDescr;
};

#pragma pack(2) 
struct RasterImageInfo {
	DWORD nSize;
	LONG nItemID;
	HANDLE hItem;
	DWORD nFlags;
	DWORD nWidth;
	DWORD nHeight;
	DWORD nResSize;
};

// XWF_AddEvent
typedef LONG (__stdcall * fptr_XWF_AddEvent) (struct EventInfo* Evt);

// XWF_GetEvent
typedef DWORD(__stdcall * fptr_XWF_GetEvent) (DWORD nEventNo, struct EventInfo* Evt);

// XWF_GetReportTableInfo
typedef LPVOID (__stdcall * fptr_XWF_GetReportTableInfo) (LPVOID pReserved, LONG nReportTableID, PLONG lpOptional);

// XWF_GetEvObjReportTableAssocs
typedef LPVOID (__stdcall * fptr_XWF_GetEvObjReportTableAssocs) (HANDLE hEvidence, LONG nFlags, PLONG lpValue);

// XWF_GetWindow
typedef HWND (__stdcall * fptr_XWF_GetWindow)(WORD nWndNo, WORD nWndIndex);

// XWF_GetProp (tested)
typedef INT64 (__stdcall * fptr_XWF_GetProp)(HANDLE hVolumeOrItem, DWORD nPropType, void* lpBuffer);

// XWF_ManageSearchTerm
typedef DWORD (__stdcall * fptr_XWF_ManageSearchTerm)(LONG nSearchTermID, LONG nProperty, DWORD* pValue);

///////////////////////////////////////////////////////////////////////////////
// Variables that store the function pointers

extern fptr_XWF_GetSize XWF_GetSize;
extern fptr_XWF_GetVolumeName XWF_GetVolumeName;
extern fptr_XWF_GetVolumeInformation XWF_GetVolumeInformation;
extern fptr_XWF_GetSectorContents XWF_GetSectorContents;
extern fptr_XWF_Read XWF_Read;
extern fptr_XWF_SectorIO XWF_SectorIO;
extern fptr_XWF_SelectVolumeSnapshot XWF_SelectVolumeSnapshot;
extern fptr_XWF_GetVSProp XWF_GetVSProp;
extern fptr_XWF_GetItemCount XWF_GetItemCount;
extern fptr_XWF_GetFileCount XWF_GetFileCount;
extern fptr_XWF_CreateItem XWF_CreateItem;
extern fptr_XWF_CreateFile XWF_CreateFile;
extern fptr_XWF_FindItem1 XWF_FindItem1;
extern fptr_XWF_GetItemName XWF_GetItemName;
extern fptr_XWF_GetItemSize XWF_GetItemSize;
extern fptr_XWF_SetItemSize XWF_SetItemSize;
extern fptr_XWF_GetItemOfs XWF_GetItemOfs;
extern fptr_XWF_SetItemOfs XWF_SetItemOfs;
extern fptr_XWF_GetItemInformation XWF_GetItemInformation;
extern fptr_XWF_SetItemInformation XWF_SetItemInformation;
extern fptr_XWF_GetItemType XWF_GetItemType;
extern fptr_XWF_SetItemType XWF_SetItemType;
extern fptr_XWF_GetItemParent XWF_GetItemParent;
extern fptr_XWF_SetItemParent XWF_SetItemParent;
extern fptr_XWF_GetHashSetAssocs XWF_GetHashSetAssocs;
extern fptr_XWF_GetReportTableAssocs XWF_GetReportTableAssocs;
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
extern fptr_XWF_ReleaseMem XWF_ReleaseMem;

extern fptr_XWF_OpenItem XWF_OpenItem;
extern fptr_XWF_Close XWF_Close;
extern fptr_XWF_CreateEvObj XWF_CreateEvObj;
extern fptr_XWF_Search XWF_Search;
extern fptr_XWF_CreateContainer XWF_CreateContainer;
extern fptr_XWF_CopyToContainer XWF_CopyToContainer;
extern fptr_XWF_CloseContainer XWF_CloseContainer;

extern fptr_XWF_GetBlock XWF_GetBlock;
extern fptr_XWF_SetBlock XWF_SetBlock;
extern fptr_XWF_GetCaseProp XWF_GetCaseProp;
extern fptr_XWF_GetFirstEvObj XWF_GetFirstEvObj;
extern fptr_XWF_GetNextEvObj XWF_GetNextEvObj;
extern fptr_XWF_OpenEvObj XWF_OpenEvObj;
extern fptr_XWF_CloseEvObj XWF_CloseEvObj;
extern fptr_XWF_GetEvObj XWF_GetEvObj;
extern fptr_XWF_GetEvObjProp XWF_GetEvObjProp;
extern fptr_XWF_GetExtractedMetadata XWF_GetExtractedMetadata;
extern fptr_XWF_GetMetadataEx XWF_GetMetadataEx;
extern fptr_XWF_GetRasterImage XWF_GetRasterImage;
extern fptr_XWF_AddExtractedMetadata XWF_AddExtractedMetadata;
extern fptr_XWF_GetHashValue XWF_GetHashValue;
extern fptr_XWF_SetHashValue XWF_SetHashValue;
extern fptr_XWF_AddEvent XWF_AddEvent;
extern fptr_XWF_GetEvent XWF_GetEvent;
extern fptr_XWF_GetReportTableInfo XWF_GetReportTableInfo;
extern fptr_XWF_GetEvObjReportTableAssocs XWF_GetEvObjReportTableAssocs;

extern fptr_XWF_GetWindow XWF_GetWindow;

extern fptr_XWF_GetProp XWF_GetProp;

extern fptr_XWF_ManageSearchTerm XWF_ManageSearchTerm;

extern fptr_XWF_Search XWF_Search;


#define XT_INIT_XWF 0x00000001 // X-Ways Forensics
#define XT_INIT_WHX 0x00000002 // WinHex
#define XT_INIT_XWI 0x00000004 // X-Ways Investigator
#define XT_INIT_BETA 0x00000008 // beta version
#define XT_INIT_QUICKCHECK 0x00000020 // called just to check whether the API accepts the calling application (used by v16.5 and later)
#define XT_INIT_ABOUTONLY 0x00000040 // called just to prepare for XT_About (used by v16.5 and later)

#define XT_ACTION_RUN 0 // simply run directly from the main menu, not for any particular volume, since v16.6
#define XT_ACTION_RVS 1 // volume snapshot refinement starting
#define XT_ACTION_LSS 2 // logical simultaneous search starting
#define XT_ACTION_PSS 3 // physical simultaneous search starting
#define XT_ACTION_DBC 4 // directory browser context menu command invoked
#define XT_ACTION_SHC 5 // search hit context menu command invoked

#define XWF_ITEM_INFO_ORIG_ID 1
#define XWF_ITEM_INFO_ATTR 2
#define XWF_ITEM_INFO_FLAGS 3
#define XWF_ITEM_INFO_DELETION 4
#define XWF_ITEM_INFO_CLASSIFICATION 5 // e.g. extracted e-mail message, alternate data stream, etc.
#define XWF_ITEM_INFO_LINKCOUNT = 6 // hard-link count
#define XWF_ITEM_INFO_FILECOUNT = 11 // how many child objects exist recursively that are files
#define XWF_ITEM_INFO_CREATIONTIME = 32
#define XWF_ITEM_INFO_MODIFICATIONTIME = 33
#define XWF_ITEM_INFO_LASTACCESSTIME = 34
#define XWF_ITEM_INFO_ENTRYMODIFICATIONTIME = 35
#define XWF_ITEM_INFO_DELETIONTIME = 36
#define XWF_ITEM_INFO_INTERNALCREATIONTIME = 37
#define XWF_ITEM_INFO_FLAGS_SET = 64 // indicates only flags that should be set, others remain unchanged
#define XWF_ITEM_INFO_FLAGS_REMOVE = 65 // indicates flags that should be removed, others remain unchanged

#define XWF_SEARCH_LOGICAL 0x00000001 // logical search instead of physical search (only logical search currently available)
#define XWF_SEARCH_TAGGEDOBJ 0x00000004 // tagged objects in volume snapshot only
#define XWF_SEARCH_MATCHCASE 0x00000010 // match case
#define XWF_SEARCH_WHOLEWORDS 0x00000020 // whole words only
#define XWF_SEARCH_GREP 0x00000040 // GREP syntax
#define XWF_SEARCH_OVERLAPPED 0x00000080 // allow overlapping hits
#define XWF_SEARCH_COVERSLACK 0x00000100 // cover slack space
#define XWF_SEARCH_COVERSLACKEX 0x00000200 // cover slack/free space transition
#define XWF_SEARCH_DECODETEXT 0x00000400 // decode text in standard file types
#define XWF_SEARCH_DECODETEXTEX 0x00000800 // decode text in specified file types // not yet supported 
#define XWF_SEARCH_1HITPERFILE 0x00001000 // 1 hit per file needed only
#define XWF_SEARCH_OMITIRRELEVANT 0x00010000 // omit files classified as irrelevant
#define XWF_SEARCH_OMITHIDDEN 0x00020000 // omit hidden files
#define XWF_SEARCH_OMITFILTERED 0x00040000 // omit files that are filtered out
#define XWF_SEARCH_DATAREDUCTION 0x00080000 // recommendable data reduction
#define XWF_SEARCH_OMITDIRS 0x00100000 // omit directories
#define XWF_SEARCH_CALLPSH 0x01000000 // see below
#define XWF_SEARCH_DISPLAYHITS 0x04000000 // display search hit list when the search completes

#define XWF_CTR_OPEN 0x00000001 // opens an existing container, all other flags ignored
#define XWF_CTR_XWFS2 0x00000002 // use new XWFS2 file system
#define XWF_CTR_SECURE 0x00000004 // mark this container as to be filled indirectly/secure
#define XWF_CTR_TOPLEVEL 0x00000008 // include evidence object names as top directory level
#define XWF_CTR_INCLDIRDATA 0x00000010 // include directory data
#define XWF_CTR_FILEPARENTS 0x00000020 // allow files as parents of files
#define XWF_CTR_USERREPORTTABLES 0x00000100 // export associations with user-created report table
#define XWF_CTR_SYSTEMREPORTTABLES 0x00000200 // export associations with system-created report tables (currently requires 0x100)
#define XWF_CTR_ALLCOMMENTS 0x00000800 // pass on comments
#define XWF_CTR_OPTIMIZE1 0x00001000 // optimize for > 1,000 items
#define XWF_CTR_OPTIMIZE2 0x00002000 // optimize for > 50,000 items
#define XWF_CTR_OPTIMIZE3 0x00004000 // optimize for > 250,000 items
#define XWF_CTR_OPTIMIZE4 0x00008000 // optimize for > 1 million items

///////////////////////////////////////////////////////////////////////////////
// Functions that X-Ways Forensics or WinHex may call

struct CallerInfo {
   byte lang, ServiceRelease;
   WORD version;
};

// XT_Init - mandatory export
LONG __stdcall XT_Init(CallerInfo info, DWORD nFlags, HANDLE hMainWnd,
   void* lpReserved);

// The following functions are optional for export
// In order to implement the functions, implement them and activate them
// in the module definition file

// XT_Done
//LONG __stdcall XT_Done(void* lpReserved);

// XT_About
//LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved);

// XT_Prepare
//LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
//   void* lpReserved);

// XT_Finalize
//LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
//   void* lpReserved);

// XT_ProcessItem
//LONG __stdcall XT_ProcessItem(LONG nItemID, void* lpReserved);

// XT_ProcessItemEx
//LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved);

// XT_ProcessSearchHit
//LONG __stdcall XT_ProcessSearchHit(struct SearchHitInfo* info);

/*#pragma pack(2)
struct PrepareSearchInfo {
   LONG iSize,
   LPWSTR lpSearchTerms,
   DWORD nBufLen,
   DWORD nFlags
};

#pragma pack(2)
struct CodePages {
   LONG iSize,
   WORD nCodePage1,
   WORD nCodePage2,
   WORD nCodePage3,
   WORD nCodePage4,
   WORD nCodePage5
};*/

// Allows to enter predefined search terms into the dialog window for use with the search
//LONG XT_PrepareSearch(struct PrepareSearchInfo* PSInfo, struct CodePages* CPages);

// Used for viewer X-Tensions
//PVOID XT_View(HANDLE hItem, LONG nItemID, HANDLE hVolume, HANDLE hEvidence,
//   PVOID lpReserved, PINT64 nResSize);

// free up memory allocated by a previous call e.g. of XT_View
//BOOL XT_ReleaseMem(PVOID lpBuffer);

#endif