/***************************************************************************************************
Module: RestoreObjectAccess.c
Author: ZChameleon @ 2016
***************************************************************************************************/


#include "RestoreAccess.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

BOOLEAN ifGoon = false;
HANDLE g_GameHandle = NULL;
HANDLE g_ThreadHanle = NULL;
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(
	IN PHANDLE_TABLE HandleTable,
	IN EXHANDLE tHandle
)
{
	ULONG_PTR i, j, k;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	EXHANDLE Handle;

	PUCHAR TableLevel1;
	PUCHAR TableLevel2;
	PUCHAR TableLevel3;

	ULONG_PTR MaxHandle;

	Handle = tHandle;
	Handle.TagBits = 0;

	MaxHandle = *(volatile ULONG*)&HandleTable->NextHandleNeedingPool;
	if (Handle.Value >= MaxHandle)
	{
		return NULL;
	}

	CapturedTable = *(volatile ULONG_PTR*)&HandleTable->TableCode;
	TableLevel = (ULONG)(CapturedTable & LEVEL_CODE_MASK);
	CapturedTable = CapturedTable - TableLevel;

	switch (TableLevel)
	{
	case 0:
	{
		TableLevel1 = (PUCHAR)CapturedTable;

		//Handle.Value相当于应用层传的伪句柄
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[Handle.Value *
			(sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

		break;
	}

	case 1:
	{
		TableLevel2 = (PUCHAR)CapturedTable;
		/*
		%0x400 = & 0x3ff
		取最低十位 因为句柄后2位无效，加上一个页只能放256项，也就是8位
		*/
		i = Handle.Value % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);
		//最后十位清0
		Handle.Value -= i;
		// 右移10位然后×4 获得第二张表的索引
		j = Handle.Value / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY));

		TableLevel1 = (PUCHAR) * (PHANDLE_TABLE_ENTRY*)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

		break;
	}

	case 2:
	{
		/*
ULONG_PTR i; 最低层的表索引
ULONG_PTR j; 中间层的表索引
ULONG_PTR k; 最上层的表索引
		
		*/
		TableLevel3 = (PUCHAR)CapturedTable;
		//一页最多能存几个项，×4是最大的序号
		//#define LOWLEVEL_COUNT (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
		i = Handle.Value % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);
		Handle.Value -= i;
		k = Handle.Value / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY));
		j = k % (MIDLEVEL_COUNT * sizeof(PHANDLE_TABLE_ENTRY));
		k -= j;
		k /= MIDLEVEL_COUNT;

		TableLevel2 = (PUCHAR) * (PHANDLE_TABLE_ENTRY*)&TableLevel3[k];
		TableLevel1 = (PUCHAR) * (PHANDLE_TABLE_ENTRY*)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

		break;
	}

	default: _assume(0);
	}

	return Entry;
}


////////////////////////////////////////////////////////////////////////////////////////////////////

//ce id  dnf id
NTSTATUS RestoreObjectAccess(ULONG32 ActiveId, ULONG32 PassiveId)
{
	ActiveId = ID1;
	PassiveId = ID2;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess = NULL;
	PEPROCESS tEprocess = NULL;
	ULONG_PTR Handle = 0;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	PVOID Object = NULL;
	POBJECT_TYPE ObjectType = NULL;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ActiveId, &EProcess)))
	{
		return Status;
	}
	
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)PassiveId, &tEprocess)))
	{
		return Status;
	}

	for (Handle = 0;; Handle += HANDLE_VALUE_INC)
	{
		Entry = ExpLookupHandleTableEntry(*(PHANDLE_TABLE*)((PUCHAR)EProcess + HANDLE_TABLE_OFFSET_WIN10), *(PEXHANDLE)&Handle);
		if (Entry == NULL)
		{
			break;
		}

		*(ULONG_PTR*)&Object = Entry->ObjectPointerBits;
		*(ULONG_PTR*)&Object <<= 4;
		if (Object == NULL)
		{
			continue;
		}

		*(ULONG_PTR*)&Object |= 0xFFFF000000000000;
		/*
		nt!_OBJECT_HEADER
		+0x030 Body             : _QUAD
		*/
		*(ULONG_PTR*)&Object += 0x30;
		ObjectType = ObGetObjectType(Object);
		if (ObjectType == NULL)
		{
			continue;
		}
		//+0x010 Name             : _UNICODE_STRING
		//+0x008 Buffer           : Ptr64 Wchar
		if (wcscmp(*(PCWSTR*)((PUCHAR)ObjectType + 0x18), L"Process") == 0)
		{
			//2e0+30h or 2e8+30h
			//+0x2e0 UniqueProcessId  : 0x00000000`0000129c Void
			if (*(PULONG32)((PUCHAR)Object + 0x2e0) == PassiveId)
			{
				KIRQL irql = WPOFFx64();
				__try {
					Entry->GrantedAccessBits = 0x1FFFFF;
				}
				__except (1) {
					DbgPrint("exception!\n");
				}
				WPONx64(irql);
				Status = STATUS_SUCCESS;
			}
		}
	}
	if(EProcess)
	ObDereferenceObject(EProcess);
	if(tEprocess)
	ObDereferenceObject(tEprocess);
	if(ifGoon)
	KeSetTimer(&Timer, DueTime, &DPC);
	return Status;
}

NTSTATUS RegitstCallbacksForProcess()
{
	NTSTATUS status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"25444");
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)preCall;
	obReg.OperationRegistration = &opReg;
	status = ObRegisterCallbacks(&obReg, &g_GameHandle);
	return status;
}
NTSTATUS RegitstCallbacksForThread()
{
	NTSTATUS status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"25444");
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsThreadType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)preCall2;
	obReg.OperationRegistration = &opReg;
	status = ObRegisterCallbacks(&obReg, &g_ThreadHanle);
	return status;
}
OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	if (strcmp((char*)PsGetProcessImageFileName(IoGetCurrentProcess()), "DNF.exe") == 0 || strcmp((char*)PsGetProcessImageFileName(IoGetCurrentProcess()), "dnf.exe") == 0)
	{
		return OB_PREOP_SUCCESS;
	}
	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
	pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = PROCESS_ALL_ACCESS;
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS preCall2(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	if (strcmp((char*)PsGetProcessImageFileName(IoGetCurrentProcess()), "DNF.exe") == 0 || strcmp((char*)PsGetProcessImageFileName(IoGetCurrentProcess()), "dnf.exe") == 0)
	{
		return OB_PREOP_SUCCESS;
	}
	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = THREAD_ALL_ACCESS;
	pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = THREAD_ALL_ACCESS;
	return OB_PREOP_SUCCESS;
}
