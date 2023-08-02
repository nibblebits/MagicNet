// Modules to control application life and create native browser window
const { app, Notification, ipcMain, webContents} = require("electron");
module.exports = require("bindings")("magicnet");
const NOTIFICATION_TITLE = "Basic Notification";
const NOTIFICATION_BODY = "Notification from the Main process";

const assert = require("assert");
const magicnet = require('./');


const { createMainWindow } = require("./windowManager");

// ...

app.whenReady().then(() => {
  createMainWindow();


// Use the module
// Use the module
let result = magicnet.magicnet_init(0);
console.log(result);

let program = magicnet.magicnet_program("electron-app");

  let counter = 0;

  // setInterval(() => {
  //   counter++;
  //   webContents.getAllWebContents().forEach(contents => {
  //     contents.send('counterUpdated', counter);
  //   });
  // }, 1000);

  // ipcMain.on('getCounter', (event) => {
  //   event.returnValue = counter;
  // });

  // ...
});

// ...
