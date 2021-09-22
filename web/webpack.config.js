var webpack = require('webpack');
var path = require('path');

module.exports = {
  entry: './public/app.js',
  output: {
    path: __dirname + '/public/dist',
    filename: 'bundle.js'
  },
  externals: ['bindings'],
  resolve: {
    alias: {
      'handsontable': path.join(__dirname, 'node_modules/handsontable/dist/handsontable.full.js'),
      'handsontable.css': path.join(__dirname, 'node_modules/handsontable/dist/handsontable.full.css'),
      'jstree.css': path.join(__dirname, 'node_modules/jstree/dist/themes/default/style.min.css'),
      'jstree-dark.css': path.join(__dirname, 'node_modules/jstree/dist/themes/default-dark/style.min.css'),
      'handlebars' : 'handlebars/dist/handlebars.js',
      "fs": false,
      "tls": false,
      "util": false,
      "assert": false,
      "net": false,
      "path": false,
      "zlib": false,
      "http": false,
      "https": false,
      "stream": false,
      "crypto": false,
    }
  },
  module: {
    rules: [
        { test: /\.css$/i,
          use: [
            "style-loader",
            "css-loader",
            "postcss-loader"
          ] },
        { test: /\.woff(2)?(\?v=[0-9]\.[0-9]\.[0-9])?$/, loader: "url-loader" },
        { test: /\.(map|ttf|eot|svg|jpg|gif|png)(\?v=[0-9]\.[0-9]\.[0-9])?$/, loader: "file-loader", options: {
            name: '[hash].[ext]',
            outputPath: '',
            publicPath: 'static/',
        } },
        {
          test: /\.s[ac]ss$/i,
          use: [
            // Creates `style` nodes from JS strings
            "style-loader",
            // Translates CSS into CommonJS
            "css-loader",
            // Compiles Sass to CSS
            "sass-loader",
          ],
        },
    ],
  },
  plugins: [
    new webpack.ContextReplacementPlugin(/bindings$/, /^$/)
  ]
}

