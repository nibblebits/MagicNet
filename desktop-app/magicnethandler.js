const { ipcMain } = require("electron");
const magicnet = require('./');
const Broadcaster = require('./broadcaster');
module.exports = require("bindings")("magicnet");

function magicNetHandleEvent(event) {
  let eventType = magicnet.magicnet_event_type(event);
  console.log('event type=:' + eventType);

  // Create an event data object
  let eventData = {
    type: eventType
  };

  // Broadcast event to renderer process
  Broadcaster.broadcast("magicnet-event-received", eventData);
}

module.exports = magicNetHandleEvent;
