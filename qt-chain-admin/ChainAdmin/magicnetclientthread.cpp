#include "magicnetclientthread.h"

extern "C" {
#include "magicnet/magicnet.h"
}

#include <iostream>

MagicNetClientThread::MagicNetClientThread(QObject *parent)
    : QObject{parent}
{
    magicnet_init();

}

MagicNetClientThread::~MagicNetClientThread()
{

}

void MagicNetClientThread::loop()
{
    // Lets try to connect to the local server and wait until we are connected
    struct magicnet_program *decentralized_program = magicnet_program("chain-admin-app");
    while (!decentralized_program)
    {
        QThread::sleep(2);
        decentralized_program = magicnet_program("chain-admin-app");
    }

    emit connected();

    while(1)
    {
        QThread::sleep(5);
    }
}
