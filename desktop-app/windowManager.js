const { BrowserWindow } = require("electron");
const path = require("path");
const indexHandler = require("./handlers/index");
const aboutHandler = require("./handlers/about");


//...
function createMainWindow() {
  const mainWindow = new BrowserWindow({
    width: 400,
    height: 200,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
    },
  });
  
  mainWindow.loadFile("forms/index.html");
  mainWindow.setMenu(null);
  indexHandler(createAboutWindow);


  return mainWindow;
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
  aboutHandler();

  return aboutWindow;
}

module.exports = {
  createMainWindow,
  createAboutWindow
};
