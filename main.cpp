#include <ntddk.h>
////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////


#define DEVICE_NAME					L"\\Device\\RestoreObjectAccess"
#define SYMBOLIC_LINK				L"\\DosDevices\\RestoreObjectAccess"
#define GLOBAL_SYMBOLIC_LINK		L"\\DosDevices\\Global\\RestoreObjectAccess"


////////////////////////////////////////////////////////////////////////////////////////////////////


#define IOCTL_RESTORE_OBJECT_ACCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X800, METHOD_BUFFERED, FILE_ANY_ACCESS)


////////////////////////////////////////////////////////////////////////////////////////////////////


#define LODWORD(l)	((ULONG32)(((ULONG_PTR)(l)) & 0xffffffff))
#define HIDWORD(l)	((ULONG32)((((ULONG_PTR)(l)) >> 32) & 0xffffffff))


////////////////////////////////////////////////////////////////////////////////////////////////////

extern KTIMER   Timer;// 注意要定义全局变量
extern KDPC     DPC;//注意要定义全局变量
extern LARGE_INTEGER DueTime;

extern ULONG ID1, ID2;

extern NTSTATUS RestoreObjectAccess(ULONG32 ActiveId, ULONG32 PassiveId);

UNICODE_STRING g_SymbolicLink;

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
		//DbgPrint("正在执行提升句柄权限\n");
		if (InputBufferLength != sizeof(ULONG64))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		ID1 = ((info*)SystemBuffer)->ID1;
		ID2 = ((info*)SystemBuffer)->ID2;
		DbgPrint("CeID = %d dnfID = %d \n", ID1, ID2);

		DueTime.QuadPart = -10000 * 100;
		KeInitializeTimer(&Timer);
		KeInitializeDpc(&DPC, (PKDEFERRED_ROUTINE)&RestoreObjectAccess, NULL);
		KeSetTimer(&Timer, DueTime, &DPC);

		Status = RestoreObjectAccess(ID1, ID2);

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

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	Status = CreateDevice(DriverObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	return Status;
}
