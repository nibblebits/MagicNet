/****************************************************************************
** Meta object code from reading C++ file 'magicnetclientmanager.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../ChainAdmin/magicnetclientmanager.h"
#include <QtCore/qmetatype.h>
#include <QtCore/QSharedPointer>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'magicnetclientmanager.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.4.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
namespace {
struct qt_meta_stringdata_MagicNetClientManager_t {
    uint offsetsAndSizes[22];
    char stringdata0[22];
    char stringdata1[34];
    char stringdata2[1];
    char stringdata3[17];
    char stringdata4[6];
    char stringdata5[16];
    char stringdata6[31];
    char stringdata7[6];
    char stringdata8[10];
    char stringdata9[13];
    char stringdata10[20];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_MagicNetClientManager_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_MagicNetClientManager_t qt_meta_stringdata_MagicNetClientManager = {
    {
        QT_MOC_LITERAL(0, 21),  // "MagicNetClientManager"
        QT_MOC_LITERAL(22, 33),  // "localServerConnectionStateUpd..."
        QT_MOC_LITERAL(56, 0),  // ""
        QT_MOC_LITERAL(57, 16),  // "LocalServerState"
        QT_MOC_LITERAL(74, 5),  // "state"
        QT_MOC_LITERAL(80, 15),  // "newNetworkEvent"
        QT_MOC_LITERAL(96, 30),  // "QSharedPointer<magicnet_event>"
        QT_MOC_LITERAL(127, 5),  // "event"
        QT_MOC_LITERAL(133, 9),  // "connected"
        QT_MOC_LITERAL(143, 12),  // "disconnected"
        QT_MOC_LITERAL(156, 19)   // "newNetworkEventSlot"
    },
    "MagicNetClientManager",
    "localServerConnectionStateUpdated",
    "",
    "LocalServerState",
    "state",
    "newNetworkEvent",
    "QSharedPointer<magicnet_event>",
    "event",
    "connected",
    "disconnected",
    "newNetworkEventSlot"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_MagicNetClientManager[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   44,    2, 0x06,    1 /* Public */,
       5,    1,   47,    2, 0x06,    3 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       8,    0,   50,    2, 0x0a,    5 /* Public */,
       9,    0,   51,    2, 0x0a,    6 /* Public */,
      10,    1,   52,    2, 0x0a,    7 /* Public */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, 0x80000000 | 6,    7,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 6,    7,

       0        // eod
};

Q_CONSTINIT const QMetaObject MagicNetClientManager::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_MagicNetClientManager.offsetsAndSizes,
    qt_meta_data_MagicNetClientManager,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_MagicNetClientManager_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<MagicNetClientManager, std::true_type>,
        // method 'localServerConnectionStateUpdated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<LocalServerState, std::false_type>,
        // method 'newNetworkEvent'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QSharedPointer<struct magicnet_event>, std::false_type>,
        // method 'connected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'disconnected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'newNetworkEventSlot'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QSharedPointer<struct magicnet_event>, std::false_type>
    >,
    nullptr
} };

void MagicNetClientManager::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<MagicNetClientManager *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->localServerConnectionStateUpdated((*reinterpret_cast< std::add_pointer_t<LocalServerState>>(_a[1]))); break;
        case 1: _t->newNetworkEvent((*reinterpret_cast< std::add_pointer_t<QSharedPointer<magicnet_event>>>(_a[1]))); break;
        case 2: _t->connected(); break;
        case 3: _t->disconnected(); break;
        case 4: _t->newNetworkEventSlot((*reinterpret_cast< std::add_pointer_t<QSharedPointer<magicnet_event>>>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (MagicNetClientManager::*)(LocalServerState );
            if (_t _q_method = &MagicNetClientManager::localServerConnectionStateUpdated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (MagicNetClientManager::*)(QSharedPointer<struct magicnet_event> );
            if (_t _q_method = &MagicNetClientManager::newNetworkEvent; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
    }
}

const QMetaObject *MagicNetClientManager::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MagicNetClientManager::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_MagicNetClientManager.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int MagicNetClientManager::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 5)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 5;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 5)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 5;
    }
    return _id;
}

// SIGNAL 0
void MagicNetClientManager::localServerConnectionStateUpdated(LocalServerState _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void MagicNetClientManager::newNetworkEvent(QSharedPointer<struct magicnet_event> _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
