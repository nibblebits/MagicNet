const { app, BrowserWindow } = require('electron');
const initializeIPC = require('./ipc.js');
const { initMagicnet } = require('./magicnetmanager');
const { createMainWindow } = require('./windowManager');

// Your existing code...

app.whenReady().then(() => {


  createMainWindow();
  // ... other lifecycle events

  app.on("window-all-closed", function () {
    if (process.platform !== "darwin") app.quit();
  });

  app.on("activate", function () {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });

  // Initialize ipc
  initializeIPC();

  // Initialize Magicnet
  initMagicnet();
});

// ... more of your existing code
