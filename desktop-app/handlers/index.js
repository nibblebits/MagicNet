const { ipcMain, dialog, webContents} = require("electron");
const aboutHandler = require("./about");

function indexHandler(createAboutWindow) {

  let counter = 0;
  let intervalID;
  
  ipcMain.on("reset-stopwatch", (event, arg) => {
    counter = 0;
  });

  ipcMain.on("toggle-stopwatch", (event, arg) => {
    console.log('Toggled:', intervalID);
  
    if(arg === "on" && !intervalID){
      console.log('Starting interval, current ID:', intervalID);
      intervalID = setInterval(() => {
        counter++;
        webContents.getAllWebContents().forEach(contents => {
          contents.send('myCounterUpdated', counter);
        });
      }, 1000);
      console.log('Interval started, new ID:', intervalID);
    } else if(arg === "off" && intervalID){
      console.log('Stopping interval, current ID:', intervalID);
      clearInterval(intervalID);
      intervalID = null; // reset the intervalID to null after clearing
      console.log('Interval stopped, new ID:', intervalID);
    }
  });
  
  
  ipcMain.handle('getCounter', async (event) => {
    return counter;
  });
  

}

module.exports = indexHandler;
