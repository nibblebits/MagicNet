// magicnetManager.js

const assert = require("assert");
const magicnet = require("bindings")("magicnet");

const Broadcaster = require("./broadcaster");
const magicNetHandleEvent = require('./magicneteventhandler');

function initMagicnet() {
  let result = magicnet.magicnet_init(0);
  console.log(result);

  let program;
  try {
    program = magicnet.magicnet_program("electron-app");
    Broadcaster.broadcast("set-connection-status-label", 'Server is connected');
    setInterval(function () {
      let event = magicnet.magicnet_next_event(program);
      if (event) {
        console.log("Found event!");
        magicNetHandleEvent(event);

      }
    }, 2000);
  } catch (error) {
    console.error("Failed to create magicnet program: ", error);
    Broadcaster.broadcast("set-connection-status-label", error);
  }
}

module.exports = {
  initMagicnet
};
