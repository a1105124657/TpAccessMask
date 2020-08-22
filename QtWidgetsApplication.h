#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApplication.h"
#include<Windows.h>
#include<qpushbutton.h>
#include<qdebug.h>
#define DEVICE_LINK_NAME    L"\\\\.\\RestoreObjectAccess"  


#define IOCTL_RESTORE_OBJECT_ACCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0X800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_Stop CTL_CODE(FILE_DEVICE_UNKNOWN, 0X801, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct tagInfo
{
    ULONG ID1;
    ULONG ID2;
}info;

class QtWidgetsApplication : public QMainWindow
{
    Q_OBJECT

public:
    QtWidgetsApplication(QWidget *parent = Q_NULLPTR);
    void RestoreAccess();
    void StopTimer();
private:
    Ui::QtWidgetsApplicationClass ui;
};
