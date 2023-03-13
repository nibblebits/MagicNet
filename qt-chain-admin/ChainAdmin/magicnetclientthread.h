#ifndef MAGICNETCLIENTTHREAD_H
#define MAGICNETCLIENTTHREAD_H

#include <QObject>
#include <QThread>
class MagicNetClientThread : public QObject
{
    Q_OBJECT
public:
    explicit MagicNetClientThread(QObject *parent = nullptr);
    virtual ~MagicNetClientThread();

public slots:
    void loop();
signals:
    void connected();
    void disconnected();
};

#endif // MAGICNETCLIENTTHREAD_H
