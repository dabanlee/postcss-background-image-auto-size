const fs = require('fs');
const postcss = require('postcss');
const autosize = require('../dist/auto-size');

fs.readFile('./test/app.css', (err, css) => {
    postcss([autosize({})])
        .process(css, {
            from: './test/app.css',
            to: './test/app.dest.css',
        })
        .then(result => {
            fs.writeFile('./test/app.dest.css', result.css, () => true);
        });
});