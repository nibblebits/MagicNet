const { ipcMain, shell } = require("electron");

function aboutHandler() {
  ipcMain.on("view_website", (event) => {
    shell.openExternal("https://dragonzap.com");
  });

  ipcMain.on('add-numbers', (event, { num1, num2 }) => {
    const result = Number(num1) + Number(num2);
    event.sender.send('add-numbers-response', result);
  });
  
}

module.exports = aboutHandler;
