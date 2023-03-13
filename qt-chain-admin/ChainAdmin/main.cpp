#include "mainwindow.h"

#include <QApplication>
#include "magicnetclientmanager.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // Start the client manager
    MagicNetClientManager::instance()->start();

    MainWindow w;
    w.show();
    return a.exec();
}
