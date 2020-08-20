export declare const hasBackground: (rule: string) => boolean;
export declare const isLocal: (url: string) => boolean;
export declare const isOlineImage: (url: string) => boolean;
export declare const isBase64Image: (url: string) => boolean;
export declare const imageSupported: (url: string) => boolean;
export declare const getImageType: (url: string) => "online" | "base64" | "unsupported";
export declare function getImageURL(rule: string): string[];
export declare function getMatchedImage(images: ImageType[], url: string): ImageType;
//# sourceMappingURL=helpers.d.ts.map