const { ipcMain, dialog} = require("electron");
const magicnet = require("./magicnetmanager");
const Broadcaster = require("./broadcaster");
const MAGICNET_EVENT_TYPES = require("./magicnetTypes");

module.exports = require("bindings")("magicnet");


// When received will launch a dialog for the provided event.
ipcMain.on('eventShowDialog', (event, arg) => {
  dialog.showMessageBox({
    type: 'info',
    title: 'Event Information',
    message: `Event type is: ${arg.type}`
  }).then(response => {
    // Handle user's response
  }).catch(err => {
    console.log(err);
  });
});


function magicNetHandleEvent(event) {
  console.log("event type=:" + event.type);

  // Broadcast event to renderer process
  Broadcaster.broadcast("magicnet-event-received", event);
}

module.exports = magicNetHandleEvent;
