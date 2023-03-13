#include "magicnetclientthread.h"
#include <iostream>

MagicNetClientThread::MagicNetClientThread(QObject *parent)
    : QObject{parent}
{

}

MagicNetClientThread::~MagicNetClientThread()
{

}

void MagicNetClientThread::loop()
{
    while(1)
    {
        QThread::sleep(5);
        emit connected();
    }
}
