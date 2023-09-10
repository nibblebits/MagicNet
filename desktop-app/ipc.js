// ipc.js

const { ipcMain, dialog } = require("electron");
const magicnet = require("./magicnetmanager");
const MAGICNET_EVENT_TYPES = require("./magicnetTypes");
const { createEventDialogWindow } = require('./windowManager');

module.exports = function initializeIPC() {
  // Event to show a dialog box
  ipcMain.on('eventShowDialog', handleEventShowDialog);
}

function handleEventShowDialog(event, data) {
  const senderWebContents = event.sender;
  const senderWindow = senderWebContents.getOwnerBrowserWindow();
  
  createEventDialogWindow(senderWindow, data);
}
