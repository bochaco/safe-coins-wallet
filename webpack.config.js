var path = require('path');
var webpack = require('webpack');

module.exports = {
    entry: './src/altcoin-wallet.js',
    output: {
        path: path.resolve(__dirname, 'lib'),
        filename: 'safe-coins-wallet.js'
    },
    module: {
        loaders: [
            {
                test: /\.js$/,
                loader: 'babel-loader',
                query: {
                    presets: ['es2015'],
                    plugins: [
                      'transform-object-rest-spread',
                      'async-to-promises'
                    ]
                }
            }
        ]
    },
    stats: {
        colors: true
    },
    devtool: 'source-map'
};
