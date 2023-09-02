// preload.js

const { contextBridge, ipcRenderer, dialog } = require('electron')
const { MagicNetEventTypeInformation} = require('./magicnetTypes');


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


contextBridge.exposeInMainWorld('MagicNetEventTypeInformation', MagicNetEventTypeInformation);

// All the Node.js APIs are available in the preload process.
// It has the same sandbox as a Chrome extension.
window.addEventListener('DOMContentLoaded', () => {

  const { ipcRenderer } = require('electron');


  const replaceText = (selector, text) => {
    const element = document.getElementById(selector)
    if (element) element.innerText = text
  }

  for (const dependency of ['chrome', 'node', 'electron']) {
    replaceText(`${dependency}-version`, process.versions[dependency])
  }
})

