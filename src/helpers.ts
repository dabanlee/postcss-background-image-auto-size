// helpers

export const hasBackground = (rule: string) => /background[^:]*.*url[^;]+/gi.test(rule);

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

export function imageSupported(url: string) {
    const http = /^http[s]?/gi;
    const base64 = /^data\:image/gi;

    return !http.test(url) && !base64.test(url);
}