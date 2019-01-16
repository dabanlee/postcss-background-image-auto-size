import resolve from 'rollup-plugin-node-resolve';
import typescript from 'rollup-plugin-typescript';

const { moduleName, destName: fileName } = require('./package.json');

module.exports = {
    input: 'src/index.ts',
    output: {
        file: `dist/${fileName}.js`,
        format: 'cjs',
        name: moduleName,
        sourcemap: true,
        globals: {
            postcss: 'postcss',
        },
    },
    plugins: [
        resolve(),
        typescript(),
    ],
    external: ['postcss', 'image-size'],
};
