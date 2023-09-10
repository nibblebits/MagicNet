const { ipcMain, dialog} = require("electron");
const magicnet = require("./magicnetmanager");
const Broadcaster = require("./broadcaster");
const MAGICNET_EVENT_TYPES = require("./magicnetTypes");

module.exports = require("bindings")("magicnet");


function magicNetHandleEvent(event) {
  console.log("event type=:" + event.type);

  // Broadcast event to renderer process
  Broadcaster.broadcast("magicnet-event-received", event);
}

module.exports = magicNetHandleEvent;
