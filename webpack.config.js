import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default [{
  entry: ['./src/index.ts'],
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },
  experiments: {
    outputModule: true
  },
  optimization: {
    minimize: false
  },
  output: {
    module: true,
    library: { type: 'module'},
    filename: 'browser.js',
    path: __dirname,
    wasmLoading: 'fetch'
  }
}]