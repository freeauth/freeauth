'use strict'

import { app, protocol, BrowserWindow } from 'electron'
import { createProtocol } from 'vue-cli-plugin-electron-builder/lib'
import { vstatus } from '@/utils/vcode'

const isDevelopment = process.env.NODE_ENV !== 'production'
const ipc = require('electron').ipcMain
const path = require('path')

// Scheme must be registered before the app is ready
protocol.registerSchemesAsPrivileged([
  { scheme: 'app', privileges: { secure: true, standard: true } }
])

async function createWindow() {
  // Create the browser window.
  const win = new BrowserWindow({
    frame: true,
    resizable: false,
    width: 800,
    height: 650,
    title: "FreeAuth Client Demo",
    icon: "assets/logo.png",
    webPreferences: {
      // Use pluginOptions.nodeIntegration, leave this alone
      // See nklayman.github.io/vue-cli-plugin-electron-builder/guide/security.html#node-integration for more info
      backgroundThrottling: false,
      preload: path.join(process.cwd(), "src/utils/preload.js"),
    }
  })

  if (process.env.WEBPACK_DEV_SERVER_URL) {
    // Load the url of the dev server if in development mode
    await win.loadURL(process.env.WEBPACK_DEV_SERVER_URL)
  } else {
    createProtocol('app')
    // Load the index.html when not in development
    win.loadURL('app://./index.html')
  }

  const { emailVerifyNativeStarter, getCurStateFromNative } = require('@/utils/backend.js');
  ipc.on('startVerification', (_, msg) => {
    console.log(msg);
    emailVerifyNativeStarter(msg,
      () => win.webContents.send('onNativeStartSuccess'),
      (error) => win.webContents.send('onNativeStartFail', error));
    let interid = setInterval(() => {
      let state = getCurStateFromNative();
      win.webContents.send('onStateChanged', state);
      if(state == vstatus.STATE_COMPLETE || state == vstatus.STATE_ERROR) // END or ERROR
      {
        console.log('finished');
        win.removeAllListeners('close');
        clearInterval(interid);
      }
    }, 50);
    
    win.on('close', (_) => clearInterval(interid));
  });
}

// Quit when all windows are closed.
app.on('window-all-closed', () => {
  // On macOS it is common for applications and their menu bar
  // to stay active until the user quits explicitly with Cmd + Q
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

app.on('activate', () => {
  // On macOS it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.on('ready', async () => {
  createWindow()
})

// Exit cleanly on request from parent process in development mode.
if (isDevelopment) {
  if (process.platform === 'win32') {
    process.on('message', (data) => {
      if (data === 'graceful-exit') {
        app.quit()
      }
    })
  } else {
    process.on('SIGTERM', () => {
      app.quit()
    })
  }
}

