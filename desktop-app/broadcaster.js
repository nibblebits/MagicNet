// broadcaster.js

const { BrowserWindow } = require('electron');

class Broadcaster {
  static broadcast(channel, message) {
    console.log('Broadcasting message:', message); 
    BrowserWindow.getAllWindows().forEach(win => {
      if (win.webContents.isLoading()) {
        win.webContents.once('did-finish-load', () => {
          win.webContents.send(channel, message);
        });
      } else {
        win.webContents.send(channel, message);
      }
    });
  }
}

module.exports = Broadcaster;
