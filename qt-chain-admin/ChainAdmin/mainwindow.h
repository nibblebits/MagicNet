#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidgetItem>
#include <QSharedPointer>
#include "magicnet/magicnet.h"
#include "magicnetclientmanager.h"
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
       void localServerConnectionStateUpdated(LocalServerState state);
       void newNetworkEvent(QSharedPointer<struct magicnet_event> event);
private:
    void addTreeRoot(QString name, QString description);
    void addTreeChild(QTreeWidgetItem *parent,
                      QString name, QString description);

    MagicNetClientManager* clientManager;
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
