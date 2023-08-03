// Modules to control application life and create native browser window
const { app, Notification, ipcMain, webContents } = require("electron");
const Broadcaster = require("./broadcaster");
module.exports = require("bindings")("magicnet");
const NOTIFICATION_TITLE = "Basic Notification";
const NOTIFICATION_BODY = "Notification from the Main process";

const assert = require("assert");
const magicnet = require("./");
const magicNetHandleEvent = require("./magicnethandler");

const { createMainWindow } = require("./windowManager");

// ...

// main.js

app.whenReady().then(() => {
  createMainWindow();

  app.on("window-all-closed", function () {
    if (process.platform !== "darwin") app.quit();
  });

  app.on("activate", function () {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });

  // Run the magicnet code after the app is ready and the windows are created.
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

  
});

// ...
