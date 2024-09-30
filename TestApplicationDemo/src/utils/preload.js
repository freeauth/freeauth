const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld("electron", {
  nativeStarter: (c) => ipcRenderer.send('startVerification', c),
  onStartSuccessListener: (l) => ipcRenderer.once('onNativeStartSuccess', l),
  onStartFailListener: (l) => ipcRenderer.once('onNativeStartFail', l),
  bindStateChangeListener: (l) => ipcRenderer.on('onStateChanged', l),
  unbindStateChangeListener: () => ipcRenderer.removeAllListeners('onStateChanged'),
});
