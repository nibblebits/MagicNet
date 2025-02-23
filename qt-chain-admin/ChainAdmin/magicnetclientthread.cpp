#include "magicnetclientthread.h"

extern "C" {
#include "magicnet/magicnet.h"
}

#include <iostream>

MagicNetClientThread::MagicNetClientThread(QObject *parent)
    : QObject{parent}
{
    magicnet_init(0, 0);

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
         // ALright lets poll the server every so often for the GUI
        struct magicnet_event* event = magicnet_next_event(decentralized_program);
        if (event)
        {
            // Alrighty we got another event cool.. Make a smart pointer and emit it
            QSharedPointer<struct magicnet_event> event_ptr(event, [](struct magicnet_event* event) {
                magicnet_event_release(event);
            });
            emit newNetworkEvent(event_ptr);
        }
        QThread::sleep(5);
    }
}
