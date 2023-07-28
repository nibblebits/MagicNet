#include "mainwindow.h"
#include "./ui_mainwindow.h"


void MainWindow::newNetworkEvent(QSharedPointer<struct magicnet_event> event)
{
    this->ui->serverStateLabel->setText("Received a new network event");
}
void MainWindow::localServerConnectionStateUpdated(LocalServerState state)
{
    if (state == MAGICNET_CLIENT_MANAGER_SERVER_ONLINE)
    {
        this->ui->serverStateLabel->setText("The local server is online");
    }
    else
    {
        this->ui->serverStateLabel->setText("Local server is disconnected\nPlease ensure your server is running\nUable to preform network activity");
    }
}
void MainWindow::addTreeChild(QTreeWidgetItem* parent, QString name, QString description)
{
     QTreeWidgetItem *treeItem = new QTreeWidgetItem();

     // QTreeWidgetItem::setText(int column, const QString & text)
     treeItem->setText(0, name);
     treeItem->setText(1, description);

     parent->addChild(treeItem);
}

void MainWindow::addTreeRoot(QString name, QString description)
{
    QTreeWidgetItem *treeItem = new QTreeWidgetItem(ui->blockchainsTreeWidget);
    treeItem->setText(0, name);
    treeItem->setText(1, description);
    addTreeChild(treeItem, name + "A", "Child_first");
    addTreeChild(treeItem, name + "B", "child_second");
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->clientManager = MagicNetClientManager::instance();
    QObject::connect(this->clientManager, &MagicNetClientManager::localServerConnectionStateUpdated, this, &MainWindow::localServerConnectionStateUpdated);
    QObject::connect(this->clientManager, &MagicNetClientManager::newNetworkEvent, this, &MainWindow::newNetworkEvent);

    emit this->localServerConnectionStateUpdated(this->clientManager->getConnectionState());
    // Set the number of columns in the tree
     ui->blockchainsTreeWidget->setColumnCount(2);

     // Add root nodes
     addTreeRoot("A", "Root_first");
     addTreeRoot("B", "Root_second");

}

MainWindow::~MainWindow()
{
    delete ui;
}

