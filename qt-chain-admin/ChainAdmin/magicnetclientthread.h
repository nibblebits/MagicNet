#ifndef MAGICNETCLIENTTHREAD_H
#define MAGICNETCLIENTTHREAD_H

#include <QObject>
#include <QThread>
#include <QSharedPointer>
extern "C" {
#include "magicnet/magicnet.h"
}
class MagicNetClientThread : public QObject
{
    Q_OBJECT
public:
    explicit MagicNetClientThread(QObject *parent = nullptr);
    virtual ~MagicNetClientThread();

public slots:
    void loop();
signals:

    void newNetworkEvent(QSharedPointer<struct magicnet_event> event);
    void connected();
    void disconnected();
};

#endif // MAGICNETCLIENTTHREAD_H
