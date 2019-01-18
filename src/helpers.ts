// helpers

export const hasBackground = (rule: string) => /background[^:]*.*url[^;]+/gi.test(rule);
export const isLocal = (url: string) => ['./', '../', '/'].map(path => url.indexOf(path) == 0).includes(true);
export const isOlineImage = (url: string) => /^http[s]?/gi.test(url);
export const isBase64Image = (url: string) => /^data\:image/gi.test(url);
export const imageSupported = (url: string) => isLocal(url) || isOlineImage(url) || isBase64Image(url);
export const getImageType = (url: string) => isOlineImage(url) ? 'online' : (isBase64Image(url) ? 'base64' : 'unsupported');

export function getImageURL(rule: string) {
    const matches = /url(?:\(['"]?)(.*?)(?:['"]?\))/gi.exec(rule);
    const original = matches ? matches[1] : '';
    const normalized = matches ? original.replace(/['"]/gi, '').replace(/\?.*$/gi, '') : '';
    
    return [original, normalized];
}

export function getMatchedImage(images: ImageType[], url: string): ImageType {
    const [matched] = images.filter(image => image.URL == url)

    return matched;
}