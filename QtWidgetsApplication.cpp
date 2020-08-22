#include "QtWidgetsApplication.h"

QtWidgetsApplication::QtWidgetsApplication(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    connect(ui.pushButton, &QPushButton::clicked, this, &QtWidgetsApplication::RestoreAccess);
    connect(ui.pushButton_2, &QPushButton::clicked, this, &QtWidgetsApplication::StopTimer);
}

void QtWidgetsApplication::RestoreAccess()
{
    DWORD ret;
    HANDLE DeviceHandle = CreateFile(DEVICE_LINK_NAME,
        GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DeviceHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }
    info info;
    info.ID1 = ui.ceId->text().toULong();
    info.ID2 = ui.dnfId->text().toULong();
    if((!info.ID1) ||(!info.ID2))
        return;
#ifdef Debug
    qDebug() << info.ID1 << info.ID2;
#endif // Debug
    
    BOOL IsOk = DeviceIoControl(DeviceHandle, IOCTL_RESTORE_OBJECT_ACCESS,
        &info,
        sizeof(info),
        NULL,
        NULL,
        &ret,
        NULL);
   
}

void QtWidgetsApplication::StopTimer()
{
    DWORD ret;
    HANDLE DeviceHandle = CreateFile(DEVICE_LINK_NAME,
        GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DeviceHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }
    BOOL IsOk = DeviceIoControl(DeviceHandle, IOCTL_Stop,
        NULL,
        NULL,
        NULL,
        NULL,
        &ret,
        NULL);
}
