// preload.js

const { contextBridge, ipcRenderer, dialog } = require('electron')


contextBridge.exposeInMainWorld(
  'api', {
    send: (channel, data) => {
      ipcRenderer.send(channel, data);
    },
    receive: (channel, func) => {
      ipcRenderer.on(channel, (event, ...args) => func(...args));
    },

  }
)

// All the Node.js APIs are available in the preload process.
// It has the same sandbox as a Chrome extension.
window.addEventListener('DOMContentLoaded', () => {

  const { ipcRenderer } = require('electron');

  ipcRenderer.on('incremented-value', (event, arg) => {
    const element = document.getElementById('incremented-value');
    if (element) element.innerText = arg;
  });

  const replaceText = (selector, text) => {
    const element = document.getElementById(selector)
    if (element) element.innerText = text
  }

  for (const dependency of ['chrome', 'node', 'electron']) {
    replaceText(`${dependency}-version`, process.versions[dependency])
  }
})

