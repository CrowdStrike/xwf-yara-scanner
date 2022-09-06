///////////////////////////////////////////////////////////////////////////////
// X-Tension API - Implementation of XT_RetrieveFunctionPointers
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "X-Tension.h"

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

///////////////////////////////////////////////////////////////////////////////
// Variables that store the function pointers

fptr_XWF_GetVolumeName XWF_GetVolumeName;
fptr_XWF_GetVolumeInformation XWF_GetVolumeInformation;
fptr_XWF_Read XWF_Read;
fptr_XWF_GetVSProp XWF_GetVSProp;
fptr_XWF_GetItemCount XWF_GetItemCount;
fptr_XWF_GetItemName XWF_GetItemName;
fptr_XWF_GetItemSize XWF_GetItemSize;
fptr_XWF_GetItemInformation XWF_GetItemInformation;
fptr_XWF_GetItemParent XWF_GetItemParent;
fptr_XWF_AddToReportTable XWF_AddToReportTable;
fptr_XWF_GetComment XWF_GetComment;
fptr_XWF_AddComment XWF_AddComment;
fptr_XWF_OutputMessage XWF_OutputMessage;
fptr_XWF_GetUserInput XWF_GetUserInput;
fptr_XWF_ShowProgress XWF_ShowProgress;
fptr_XWF_SetProgressPercentage XWF_SetProgressPercentage;
fptr_XWF_SetProgressDescription XWF_SetProgressDescription;
fptr_XWF_ShouldStop XWF_ShouldStop;
fptr_XWF_HideProgress XWF_HideProgress;
fptr_XWF_GetEvObjProp XWF_GetEvObjProp;
fptr_XWF_GetHashValue XWF_GetHashValue;
fptr_XWF_GetProp XWF_GetProp;
fptr_XWF_CreateFile XWF_CreateFile;


///////////////////////////////////////////////////////////////////////////////
// XT_RetrieveFunctionPointers - call this function before calling anything else

LONG __stdcall XT_RetrieveFunctionPointers()
{
	HMODULE Hdl = GetModuleHandle(NULL);

	XWF_GetVolumeName = (fptr_XWF_GetVolumeName)GetProcAddress(Hdl, "XWF_GetVolumeName");
	XWF_GetVolumeInformation = (fptr_XWF_GetVolumeInformation)GetProcAddress(Hdl, "XWF_GetVolumeInformation");
	XWF_Read = (fptr_XWF_Read)GetProcAddress(Hdl, "XWF_Read");
	XWF_GetVSProp = (fptr_XWF_GetVSProp)GetProcAddress(Hdl, "XWF_GetVSProp");
	XWF_GetItemCount = (fptr_XWF_GetItemCount)GetProcAddress(Hdl, "XWF_GetItemCount");
	XWF_GetItemName = (fptr_XWF_GetItemName)GetProcAddress(Hdl, "XWF_GetItemName");
	XWF_GetItemSize = (fptr_XWF_GetItemSize)GetProcAddress(Hdl, "XWF_GetItemSize");
	XWF_GetItemInformation = (fptr_XWF_GetItemInformation)GetProcAddress(Hdl, "XWF_GetItemInformation");
	XWF_GetItemParent = (fptr_XWF_GetItemParent)GetProcAddress(Hdl, "XWF_GetItemParent");
	XWF_AddToReportTable = (fptr_XWF_AddToReportTable)GetProcAddress(Hdl, "XWF_AddToReportTable");
	XWF_GetComment = (fptr_XWF_GetComment)GetProcAddress(Hdl, "XWF_GetComment");
	XWF_AddComment = (fptr_XWF_AddComment)GetProcAddress(Hdl, "XWF_AddComment");
	XWF_CreateFile = (fptr_XWF_CreateFile)GetProcAddress(Hdl, "XWF_CreateFile");
	XWF_OutputMessage = (fptr_XWF_OutputMessage)GetProcAddress(Hdl, "XWF_OutputMessage");
	XWF_GetUserInput = (fptr_XWF_GetUserInput)GetProcAddress(Hdl, "XWF_GetUserInput");
	XWF_ShowProgress = (fptr_XWF_ShowProgress)GetProcAddress(Hdl, "XWF_ShowProgress");
	XWF_SetProgressPercentage = (fptr_XWF_SetProgressPercentage)GetProcAddress(Hdl, "XWF_SetProgressPercentage");
	XWF_SetProgressDescription = (fptr_XWF_SetProgressDescription)GetProcAddress(Hdl, "XWF_SetProgressDescription");
	XWF_ShouldStop = (fptr_XWF_ShouldStop)GetProcAddress(Hdl, "XWF_ShouldStop");
	XWF_HideProgress = (fptr_XWF_HideProgress)GetProcAddress(Hdl, "XWF_HideProgress");
	XWF_GetEvObjProp = (fptr_XWF_GetEvObjProp)GetProcAddress(Hdl, "XWF_GetEvObjProp");
	XWF_GetHashValue = (fptr_XWF_GetHashValue)GetProcAddress(Hdl, "XWF_GetHashValue");
	XWF_GetProp = (fptr_XWF_GetProp)GetProcAddress(Hdl, "XWF_GetProp");

	return 1;
}

