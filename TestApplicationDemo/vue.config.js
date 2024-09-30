// const { defineConfig } = require('@vue/cli-service')
// const path = require('path');
// const CopyWebpackPlugin = require('copy-webpack-plugin');
// const webpack = require("webpack");

module.exports = {
  productionSourceMap: false,
  devServer: {
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
    // for tests
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        secure: false,
        changeOrigin: true,
        pathRewrite: { '^/api': '' },
      }
    }
  },
  pluginOptions: {
    electronBuilder: {
      externals: ['koffi'],
      builderOptions: {
        extraFiles: ["./libs"]
      },
    }
  },
}
