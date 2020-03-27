export default {
    input: 'src/index.js',
    output: [
        {
            file: 'index.cjs.js',
            format: 'cjs'
        },
        {
            file: 'index.esm.js',
            format: 'es'
        }
    ],
    external: ['bigint-crypto-utils','bigint-conversion']
};
