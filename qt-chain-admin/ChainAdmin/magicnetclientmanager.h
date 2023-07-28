#ifndef MAGICNETCLIENTMANAGER_H
#define MAGICNETCLIENTMANAGER_H

#include <QObject>
#include <QMutex>
#include <QMutexLocker>
#include <QThread>
#include <QSharedPointer>
#include "magicnetclientthread.h"
extern "C" {
#include "magicnet/magicnet.h"
}
enum LocalServerState
{
    MAGICNET_CLIENT_MANAGER_SERVER_OFFLINE,
    MAGICNET_CLIENT_MANAGER_SERVER_ONLINE
};
class MagicNetClientManager : public QObject
{
    Q_OBJECT
public:
    MagicNetClientManager();
    virtual ~MagicNetClientManager();
    static MagicNetClientManager* instance();
    LocalServerState getConnectionState();

    void start();
    void stop();

public slots:
        void connected();
        void disconnected();
        void newNetworkEventSlot(QSharedPointer<struct magicnet_event> event);
signals:
        void localServerConnectionStateUpdated(LocalServerState state);
        void newNetworkEvent(QSharedPointer<struct magicnet_event> event);


protected:
        void setConnectionState(LocalServerState state);
private:

        mutable QMutex mutex_;
        LocalServerState serverState;
        QThread threadObj;
        MagicNetClientThread clientThread;

};

#endif // MAGICNETCLIENTMANAGER_H
