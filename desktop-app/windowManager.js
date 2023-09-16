const { BrowserWindow } = require("electron");
const { MagicNetEventTypeInformation } = require("./magicnetTypes");
const path = require("path");

//...
function createMainWindow() {
  const mainWindow = new BrowserWindow({
    width: 1000,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
    },
  });

  mainWindow.loadFile("forms/index.html");

  return mainWindow;
}

function createEventDialogWindow(parentWindow, data) {
  const eventDialogWindow = new BrowserWindow({
    width: 400,
    height: 400,
    parent: parentWindow,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
    },
  });

  eventDialogWindow.webContents.on("did-finish-load", () => {
    eventDialogWindow.webContents.send("initialize-data", data);
  });

  const isValidIndex = (index, array) => index >= 0 && index < array.length;

  if (isValidIndex(data.type, MagicNetEventTypeInformation)) {
    const { event_file } = MagicNetEventTypeInformation[data.type];
    eventDialogWindow.loadFile(event_file);
  } else {
    console.error(`Invalid index: ${data.type}`);
    // Handle error as needed
  }
  

  return eventDialogWindow;
}

function createAboutWindow() {
  const aboutWindow = new BrowserWindow({
    width: 256,
    height: 256,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
    },
  });

  aboutWindow.loadFile("forms/about.html");
  return aboutWindow;
}

module.exports = {
  createMainWindow,
  createAboutWindow,
  createEventDialogWindow,
};
