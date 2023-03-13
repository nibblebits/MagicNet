#ifndef MAGICNETCLIENTMANAGER_H
#define MAGICNETCLIENTMANAGER_H

#include <QObject>
#include <QMutex>
#include <QMutexLocker>
#include <QThread>
#include "magicnetclientthread.h"
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
signals:
        void localServerConnectionStateUpdated(LocalServerState state);

protected:
        void setConnectionState(LocalServerState state);
private:

        mutable QMutex mutex_;
        LocalServerState serverState;
        QThread threadObj;
        MagicNetClientThread clientThread;

};

#endif // MAGICNETCLIENTMANAGER_H
