#include <ntddk.h>
////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////


#define DEVICE_NAME					L"\\Device\\RestoreObjectAccess"
#define SYMBOLIC_LINK				L"\\DosDevices\\RestoreObjectAccess"
#define GLOBAL_SYMBOLIC_LINK		L"\\DosDevices\\Global\\RestoreObjectAccess"


////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _LDR_DATA                         // 24 elements, 0xE0 bytes (sizeof)
{
	struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
	struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
	struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG32      SizeOfImage;
	UINT8        _PADDING0_[0x4];
	struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
	struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
	ULONG32      Flags;
	UINT16       LoadCount;
	UINT16       TlsIndex;
	union
	{
		struct _LIST_ENTRY HashLinks;
		struct
		{
			VOID* SectionPointer;
			ULONG32      CheckSum;
			UINT8        _PADDING1_[0x4];
		};
	};

	union
	{
		ULONG32      TimeDateStamp;
		VOID* LoadedImports;
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	VOID* PatchInformation;
	struct _LIST_ENTRY ForwarderLinks;
	struct _LIST_ENTRY ServiceTagLinks;
	struct _LIST_ENTRY StaticLinks;
	VOID* ContextInformation;
	UINT64       OriginalBase;
	union _LARGE_INTEGER LoadTime;
}LDR_DATA, * PLDR_DATA;

#define IOCTL_RESTORE_OBJECT_ACCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_Stop CTL_CODE(FILE_DEVICE_UNKNOWN, 0X801, METHOD_BUFFERED, FILE_ANY_ACCESS)
////////////////////////////////////////////////////////////////////////////////////////////////////


#define LODWORD(l)	((ULONG32)(((ULONG_PTR)(l)) & 0xffffffff))
#define HIDWORD(l)	((ULONG32)((((ULONG_PTR)(l)) >> 32) & 0xffffffff))


////////////////////////////////////////////////////////////////////////////////////////////////////

extern KTIMER   Timer;// 注意要定义全局变量
extern KDPC     DPC;//注意要定义全局变量
extern LARGE_INTEGER DueTime;

extern ULONG ID1, ID2;

extern NTSTATUS RestoreObjectAccess(ULONG32 ActiveId, ULONG32 PassiveId);

extern BOOLEAN ifGoon;

UNICODE_STRING g_SymbolicLink;
extern NTSTATUS RegitstCallbacksForProcess();

extern NTSTATUS RegitstCallbacksForThread();
typedef struct _info
{
	ULONG ID1;
	ULONG ID2;
}info;
////////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION IoStackLocation = NULL;
	PVOID SystemBuffer = NULL;
	ULONG IoControlCode = 0;
	ULONG InputBufferLength = 0;
	ULONG OutputBufferLength = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);

	IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
	SystemBuffer = Irp->AssociatedIrp.SystemBuffer;

	switch (IoControlCode)
	{
	case IOCTL_RESTORE_OBJECT_ACCESS:
	{
#ifdef Debug
		DbgPrint("正在执行提升句柄权限\n");
#endif
		if (InputBufferLength != sizeof(ULONG64))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		ifGoon = TRUE;

		ID1 = ((info*)SystemBuffer)->ID1;
		ID2 = ((info*)SystemBuffer)->ID2;
#ifdef Debug
		DbgPrint("CeID = %d dnfID = %d \n", ID1, ID2);
#endif // Debug
		DueTime.QuadPart = -10000 * 100;
		KeInitializeTimer(&Timer);
		KeInitializeDpc(&DPC, (PKDEFERRED_ROUTINE)&RestoreObjectAccess, NULL);
		KeSetTimer(&Timer, DueTime, &DPC);
		
		

		break;
	}
	case IOCTL_Stop:
	{
		ifGoon = FALSE;
		KeWaitForSingleObject(&Timer, Executive, KernelMode, FALSE, NULL);
		KeCancelTimer(&Timer);
		DbgPrint("CancelTimer!\n");
		break;
	}
	default:
		break;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}


////////////////////////////////////////////////////////////////////////////////////////////////////


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&g_SymbolicLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}


////////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	PDEVICE_OBJECT DeviceObject;

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	// Using "Global DosDevice Directory" or not
	if (IoIsWdmVersionAvailable(1, 0x10))
	{
		// Windows 2000 or later
		RtlInitUnicodeString(&g_SymbolicLink, GLOBAL_SYMBOLIC_LINK);
	}
	else
	{
		// Windows Me/98
		RtlInitUnicodeString(&g_SymbolicLink, SYMBOLIC_LINK);
	}

	Status = IoCreateSymbolicLink(&g_SymbolicLink, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(DeviceObject);
		return Status;
	}

	return Status;
}


////////////////////////////////////////////////////////////////////////////////////////////////////

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	NTSTATUS Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(RegisterPath);

	//CheckSystemVersion();
	PLDR_DATA ldr;
	ldr = (PLDR_DATA)DriverObject->DriverSection;
	ldr->Flags |= 0x20;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	Status = CreateDevice(DriverObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	RegitstCallbacksForProcess();
	RegitstCallbacksForThread();

	return Status;
}
