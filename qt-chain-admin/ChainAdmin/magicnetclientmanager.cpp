#include "magicnetclientmanager.h"
#include <stdexcept>

MagicNetClientManager::MagicNetClientManager() : QObject(nullptr)
{
    this->serverState = MAGICNET_CLIENT_MANAGER_SERVER_OFFLINE;
    QObject::connect(&this->threadObj, &QThread::started, &this->clientThread, &MagicNetClientThread::loop);
    QObject::connect(&this->clientThread, &MagicNetClientThread::connected, this, &MagicNetClientManager::connected);
    QObject::connect(&this->clientThread, &MagicNetClientThread::disconnected, this, &MagicNetClientManager::disconnected);

}

MagicNetClientManager::~MagicNetClientManager()
{

}


void MagicNetClientManager::setConnectionState(LocalServerState state)
{
    QMutexLocker locker(&this->mutex_);
    this->serverState = state;
    emit localServerConnectionStateUpdated(state);
}

LocalServerState MagicNetClientManager::getConnectionState()
{
    QMutexLocker locker(&this->mutex_);
    return this->serverState;
}

void MagicNetClientManager::connected()
{
    this->setConnectionState(MAGICNET_CLIENT_MANAGER_SERVER_ONLINE);
}

void MagicNetClientManager::disconnected()
{
    this->setConnectionState(MAGICNET_CLIENT_MANAGER_SERVER_OFFLINE);

}

void MagicNetClientManager::start()
{
    QMutexLocker locker(&this->mutex_);
    if (this->threadObj.isRunning())
    {
        throw std::runtime_error("The main client thread was already running");
    }

    this->clientThread.moveToThread(&this->threadObj);
    this->threadObj.start();

}

void MagicNetClientManager::stop()
{

}

MagicNetClientManager* MagicNetClientManager::instance()
{
   static MagicNetClientManager* manager = new MagicNetClientManager();
   return manager;
}
