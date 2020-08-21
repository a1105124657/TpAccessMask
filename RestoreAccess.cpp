/***************************************************************************************************
Module: RestoreObjectAccess.c
Author: ZChameleon @ 2016
***************************************************************************************************/


#include "RestoreAccess.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

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

	PAGED_CODE();

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

		i = Handle.Value % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);
		/*
		
		*/
		Handle.Value -= i;
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


NTSTATUS RestoreObjectAccess(ULONG32 ActiveId, ULONG32 PassiveId)
{
	ActiveId = ID1;
	PassiveId = ID2;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess = NULL;
	ULONG_PTR Handle = 0;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	PVOID Object = NULL;
	POBJECT_TYPE ObjectType = NULL;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ActiveId, &EProcess)))
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
			//int a = *(PULONG32)((PUCHAR)Object) + 0x2e8; 2e0 or 2e8
			//DbgPrint("a = %d\n", a);
			//char* name = (char*)((PUCHAR)Object + 0x450);
		///	DbgPrint("已执行 目标进程映像 %s\n", name);
			if (*(PULONG32)((PUCHAR)Object + 0x2e8) == PassiveId)
			{
				//DbgPrint("已执行%s提升权限\n",name);
				KIRQL irql = WPOFFx64();
				__try {
					Entry->GrantedAccessBits = 0x1FFFFF;
				}
				__except (1) {
					DbgPrint("unhandled exception\n");
				}
				WPONx64(irql);
				Status = STATUS_SUCCESS;
			}
		}
	}

	ObDereferenceObject(EProcess);
	KeSetTimer(&Timer, DueTime, &DPC);
	return Status;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
