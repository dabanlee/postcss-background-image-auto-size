'use strict';

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var path = _interopDefault(require('path'));
var sizeOf = _interopDefault(require('image-size'));
var postcss = require('postcss');

// helpers
var hasBackground = function (rule) { return /background[^:]*.*url[^;]+/gi.test(rule); };
var isLocal = function (url) { return ['./', '../', '/'].map(function (path$$1) { return url.indexOf(path$$1) == 0; }).includes(true); };
var isOlineImage = function (url) { return /^http[s]?/gi.test(url); };
var isBase64Image = function (url) { return /^data\:image/gi.test(url); };
var imageSupported = function (url) { return isLocal(url) || isOlineImage(url) || isBase64Image(url); };
var getImageType = function (url) { return isOlineImage(url) ? 'online' : (isBase64Image(url) ? 'base64' : 'unsupported'); };
function getImageURL(rule) {
    var matches = /url(?:\(['"]?)(.*?)(?:['"]?\))/gi.exec(rule);
    var original = matches ? matches[1] : '';
    var normalized = matches ? original.replace(/['"]/gi, '').replace(/\?.*$/gi, '') : '';
    return [original, normalized];
}
function getMatchedImage(images, url) {
    var matched = images.filter(function (image) { return image.URL == url; })[0];
    return matched;
}
//# sourceMappingURL=helpers.js.map

var PLUGIN_NAME = 'auto-image-size';
var index = postcss.plugin(PLUGIN_NAME, function () {
    return function (root) {
        root.walkComments(function (comment) { return comment.remove(); });
        var images = extractImages(root);
        root.walkDecls(/^background(-image)?$/, function (declare) {
            var rule = declare.parent;
            var ruleString = rule.toString();
            if (!hasBackground(ruleString))
                return false;
            var _a = getImageURL(ruleString), URL = _a[1];
            var image = getMatchedImage(images, URL);
            if (!image)
                return false;
            if (image.type == 'online')
                return console.log("online image not supported for the time being");
            var _b = sizeOf(image.path), width = _b.width, height = _b.height;
            declare.cloneAfter({
                type: 'decl',
                prop: 'width',
                value: width + "px"
            }).cloneAfter({
                type: 'decl',
                prop: 'height',
                value: height + "px"
            });
        });
    };
});
function extractImages(root) {
    var images = [];
    root.walkRules(function (rule) {
        var styleFilePath = root.source.input.file;
        var ruleString = rule.toString();
        var image = {
            type: null,
            path: null,
            URL: null,
            originURL: null
        };
        if (hasBackground(ruleString)) {
            var _a = getImageURL(ruleString), originURL = _a[0], URL = _a[1];
            image.type = getImageType(URL);
            image.URL = URL;
            image.originURL = originURL;
            if (imageSupported(image.URL)) {
                image.path = path.resolve(path.dirname(styleFilePath), image.URL);
                images.push(image);
            }
            else {
                console.log("image not supported");
            }
        }
    });
    return images;
}

module.exports = index;
//# sourceMappingURL=auto-size.js.map
