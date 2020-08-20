(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory(require('path'), require('fs'), require('os')) :
  typeof define === 'function' && define.amd ? define(['path', 'fs', 'os'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, global.ImageAutoSize = factory(global.path, global.fs, global.os));
}(this, (function (path, fs, os) { 'use strict';

  function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

  var path__default = /*#__PURE__*/_interopDefaultLegacy(path);
  var fs__default = /*#__PURE__*/_interopDefaultLegacy(fs);
  var os__default = /*#__PURE__*/_interopDefaultLegacy(os);

  function isBMP (buffer) {
    return ('BM' === buffer.toString('ascii', 0, 2));
  }

  function calculate (buffer) {
    return {
      'width': buffer.readUInt32LE(18),
      'height': Math.abs(buffer.readInt32LE(22))
    };
  }

  var bmp = {
    'detect': isBMP,
    'calculate': calculate
  };

  var TYPE_ICON = 1;

  /**
   * ICON Header
   *
   * | Offset | Size | Purpose                                                                                   |
   * | 0	    | 2    | Reserved. Must always be 0.                                                               |
   * | 2      | 2    | Image type: 1 for icon (.ICO) image, 2 for cursor (.CUR) image. Other values are invalid. |
   * | 4      | 2    | Number of images in the file.                                                             |
   *
   **/
  var SIZE_HEADER = 2 + 2 + 2; // 6

  /**
   * Image Entry
   *
   * | Offset | Size | Purpose                                                                                          |
   * | 0	    | 1    | Image width in pixels. Can be any number between 0 and 255. Value 0 means width is 256 pixels.   |
   * | 1      | 1    | Image height in pixels. Can be any number between 0 and 255. Value 0 means height is 256 pixels. |
   * | 2      | 1    | Number of colors in the color palette. Should be 0 if the image does not use a color palette.    |
   * | 3      | 1    | Reserved. Should be 0.                                                                           |
   * | 4      | 2    | ICO format: Color planes. Should be 0 or 1.                                                      |
   * |        |      | CUR format: The horizontal coordinates of the hotspot in number of pixels from the left.         |
   * | 6      | 2    | ICO format: Bits per pixel.                                                                      |
   * |        |      | CUR format: The vertical coordinates of the hotspot in number of pixels from the top.            |
   * | 8      | 4    | The size of the image's data in bytes                                                            |
   * | 12     | 4    | The offset of BMP or PNG data from the beginning of the ICO/CUR file                             |
   *
   **/
  var SIZE_IMAGE_ENTRY = 1 + 1 + 1 + 1 + 2 + 2 + 4 + 4; // 16

  function isICO (buffer) {
    var type;
    if (buffer.readUInt16LE(0) !== 0) {
      return false;
    }
    type = buffer.readUInt16LE(2);
    return type === TYPE_ICON;
  }

  function getSizeFromOffset(buffer, offset) {
    var value = buffer.readUInt8(offset);
    return value === 0 ? 256 : value;
  }

  function getImageSize(buffer, imageIndex) {
    var offset = SIZE_HEADER + (imageIndex * SIZE_IMAGE_ENTRY);
    return {
      'width': getSizeFromOffset(buffer, offset),
      'height': getSizeFromOffset(buffer, offset + 1)
    };
  }

  function calculate$1 (buffer) {
    var 
      nbImages = buffer.readUInt16LE(4),
      result = getImageSize(buffer, 0),
      imageIndex;
      
    if (nbImages === 1) {
      return result;
    }
    
    result.images = [{
      width: result.width,
      height: result.height
    }];
    
    for (imageIndex = 1; imageIndex < nbImages; imageIndex += 1) {
      result.images.push(getImageSize(buffer, imageIndex));
    }
    
    return result;
  }

  var ico = {
    'detect': isICO,
    'calculate': calculate$1
  };

  var TYPE_CURSOR = 2;

  function isCUR (buffer) {
    var type;
    if (buffer.readUInt16LE(0) !== 0) {
      return false;
    }
    type = buffer.readUInt16LE(2);
    return type === TYPE_CURSOR;
  }

  var cur = {
    'detect': isCUR,
    'calculate': ico.calculate
  };

  function isDDS(buffer){
    return buffer.readUInt32LE(0) === 0x20534444;
  }

  function calculate$2(buffer){
    // read file resolution metadata
    return {
      'height': buffer.readUInt32LE(12),
      'width': buffer.readUInt32LE(16)
    };
  }

  var dds = {
    'detect': isDDS,
    'calculate': calculate$2
  };

  var gifRegexp = /^GIF8[79]a/;
  function isGIF (buffer) {
    var signature = buffer.toString('ascii', 0, 6);
    return (gifRegexp.test(signature));
  }

  function calculate$3(buffer) {
    return {
      'width': buffer.readUInt16LE(6),
      'height': buffer.readUInt16LE(8)
    };
  }

  var gif = {
    'detect': isGIF,
    'calculate': calculate$3
  };

  /**
   * ICNS Header
   *
   * | Offset | Size | Purpose                                                |
   * | 0	    | 4    | Magic literal, must be "icns" (0x69, 0x63, 0x6e, 0x73) |
   * | 4      | 4    | Length of file, in bytes, msb first.                   |
   *
   **/
  var SIZE_HEADER$1 = 4 + 4; // 8
  var FILE_LENGTH_OFFSET = 4; // MSB => BIG ENDIAN

  /**
   * Image Entry
   *
   * | Offset | Size | Purpose                                                          |
   * | 0	    | 4    | Icon type, see OSType below.                                     |
   * | 4      | 4    | Length of data, in bytes (including type and length), msb first. |
   * | 8      | n    | Icon data                                                        |
   *
   **/
  var ENTRY_LENGTH_OFFSET = 4; // MSB => BIG ENDIAN

  function isICNS (buffer) {
    return ('icns' === buffer.toString('ascii', 0, 4));
  }

  var ICON_TYPE_SIZE = {
    ICON: 32,
    'ICN#': 32,
    // m => 16 x 16
    'icm#': 16,
    icm4: 16,
    icm8: 16,
    // s => 16 x 16
    'ics#': 16,
    ics4: 16,
    ics8: 16,
    is32: 16,
    s8mk: 16,
    icp4: 16,
    // l => 32 x 32
    icl4: 32,
    icl8: 32,
    il32: 32,
    l8mk: 32,
    icp5: 32,
    ic11: 32,
    // h => 48 x 48
    ich4: 48,
    ich8: 48,
    ih32: 48,
    h8mk: 48,
    // . => 64 x 64
    icp6: 64,
    ic12: 32,
    // t => 128 x 128
    it32: 128,
    t8mk: 128,
    ic07: 128,
    // . => 256 x 256
    ic08: 256,
    ic13: 256,
    // . => 512 x 512
    ic09: 512,
    ic14: 512,
    // . => 1024 x 1024
    ic10: 1024,
  };

  function readImageHeader(buffer, imageOffset) {
    var imageLengthOffset = imageOffset + ENTRY_LENGTH_OFFSET;
    // returns [type, length]
    return [
      buffer.toString('ascii', imageOffset, imageLengthOffset),
      buffer.readUInt32BE(imageLengthOffset)
    ];
  }

  function getImageSize$1(type) {
    var size = ICON_TYPE_SIZE[type];
    return { width: size, height: size, type: type };
  }

  function calculate$4 (buffer) {
    var
      bufferLength = buffer.length,
      imageOffset = SIZE_HEADER$1,
      fileLength = buffer.readUInt32BE(FILE_LENGTH_OFFSET),
      imageHeader,
      imageSize,
      result;

    imageHeader = readImageHeader(buffer, imageOffset);
    imageSize = getImageSize$1(imageHeader[0]);
    imageOffset += imageHeader[1];

    if (imageOffset === fileLength) {
      return imageSize;
    }
    
    result = {
      width: imageSize.width,
      height: imageSize.height,
      images: [imageSize]
    };
    
    while (imageOffset < fileLength && imageOffset < bufferLength) {
      imageHeader = readImageHeader(buffer, imageOffset);
      imageSize = getImageSize$1(imageHeader[0]);
      imageOffset += imageHeader[1];
      result.images.push(imageSize);
    }
    
    return result;
  }

  var icns = {
    'detect': isICNS,
    'calculate': calculate$4
  };

  // Abstract reading multi-byte unsigned integers
  function readUInt (buffer, bits, offset, isBigEndian) {
    offset = offset || 0;
    var endian = isBigEndian ? 'BE' : 'LE';
    var method = buffer['readUInt' + bits + endian];
    return method.call(buffer, offset);
  }

  var readUInt_1 = readUInt;

  // NOTE: we only support baseline and progressive JPGs here
  // due to the structure of the loader class, we only get a buffer
  // with a maximum size of 4096 bytes. so if the SOF marker is outside
  // if this range we can't detect the file size correctly.

  function isJPG (buffer) { //, filepath
    var SOIMarker = buffer.toString('hex', 0, 2);
    return ('ffd8' === SOIMarker);
  }

  function isEXIF (buffer) { //, filepath
    var exifMarker = buffer.toString('hex', 2, 6);
    return (exifMarker === '45786966'); // 'Exif'
  }

  function extractSize (buffer, i) {
    return {
      'height' : buffer.readUInt16BE(i),
      'width' : buffer.readUInt16BE(i + 2)
    };
  }

  var APP1_DATA_SIZE_BYTES = 2;
  var EXIF_HEADER_BYTES = 6;
  var TIFF_BYTE_ALIGN_BYTES = 2;
  var BIG_ENDIAN_BYTE_ALIGN = '4d4d';
  var LITTLE_ENDIAN_BYTE_ALIGN = '4949';

  // Each entry is exactly 12 bytes
  var IDF_ENTRY_BYTES = 12;
  var NUM_DIRECTORY_ENTRIES_BYTES = 2;

  function validateExifBlock (buffer, i) {
    // Skip APP1 Data Size
    var exifBlock = buffer.slice(APP1_DATA_SIZE_BYTES, i);

    // Consider byte alignment
    var byteAlign = exifBlock.toString('hex', EXIF_HEADER_BYTES, EXIF_HEADER_BYTES + TIFF_BYTE_ALIGN_BYTES);

    // Ignore Empty EXIF. Validate byte alignment
    var isBigEndian = byteAlign === BIG_ENDIAN_BYTE_ALIGN;
    var isLittleEndian = byteAlign === LITTLE_ENDIAN_BYTE_ALIGN;

    if (isBigEndian || isLittleEndian) {
      return extractOrientation(exifBlock, isBigEndian);
    }
  }

  function extractOrientation (exifBlock, isBigEndian) {
    // TODO: assert that this contains 0x002A
    // var STATIC_MOTOROLA_TIFF_HEADER_BYTES = 2;
    // var TIFF_IMAGE_FILE_DIRECTORY_BYTES = 4;

    // TODO: derive from TIFF_IMAGE_FILE_DIRECTORY_BYTES
    var idfOffset = 8;

    // IDF osset works from right after the header bytes
    // (so the offset includes the tiff byte align)
    var offset = EXIF_HEADER_BYTES + idfOffset;

    var idfDirectoryEntries = readUInt_1(exifBlock, 16, offset, isBigEndian);

    var start;
    var end;
    for (var directoryEntryNumber = 0; directoryEntryNumber < idfDirectoryEntries; directoryEntryNumber++) {
      start = offset + NUM_DIRECTORY_ENTRIES_BYTES + (directoryEntryNumber * IDF_ENTRY_BYTES);
      end = start + IDF_ENTRY_BYTES;

      // Skip on corrupt EXIF blocks
      if (start > exifBlock.length) {
        return;
      }

      var block = exifBlock.slice(start, end);
      var tagNumber = readUInt_1(block, 16, 0, isBigEndian);

      // 0x0112 (decimal: 274) is the `orientation` tag ID
      if (tagNumber === 274) {
        var dataFormat = readUInt_1(block, 16, 2, isBigEndian);
        if (dataFormat !== 3) {
          return;
        }

        // unsinged int has 2 bytes per component
        // if there would more than 4 bytes in total it's a pointer
        var numberOfComponents = readUInt_1(block, 32, 4, isBigEndian);
        if (numberOfComponents !== 1) {
          return;
        }

        return readUInt_1(block, 16, 8, isBigEndian);
      }
    }
  }

  function validateBuffer (buffer, i) {
    // index should be within buffer limits
    if (i > buffer.length) {
      throw new TypeError('Corrupt JPG, exceeded buffer limits');
    }
    // Every JPEG block must begin with a 0xFF
    if (buffer[i] !== 0xFF) {
      throw new TypeError('Invalid JPG, marker table corrupted');
    }
  }

  function calculate$5 (buffer) {
    // Skip 4 chars, they are for signature
    buffer = buffer.slice(4);

    var orientation;

    var i, next;
    while (buffer.length) {
      // read length of the next block
      i = buffer.readUInt16BE(0);

      if (isEXIF(buffer)) {
        orientation = validateExifBlock(buffer, i);
      }

      // ensure correct format
      validateBuffer(buffer, i);

      // 0xFFC0 is baseline standard(SOF)
      // 0xFFC1 is baseline optimized(SOF)
      // 0xFFC2 is progressive(SOF2)
      next = buffer[i + 1];
      if (next === 0xC0 || next === 0xC1 || next === 0xC2) {
        var size = extractSize(buffer, i + 5);

        if (!orientation) {
          return size;
        }

        return {
          width: size.width,
          height: size.height,
          orientation: orientation
        };
      }

      // move to the next block
      buffer = buffer.slice(i + 2);
    }

    throw new TypeError('Invalid JPG, no size found');
  }

  var jpg = {
    'detect': isJPG,
    'calculate': calculate$5
  };

  var pngSignature = 'PNG\r\n\x1a\n';
  var pngImageHeaderChunkName = 'IHDR';

  // Used to detect "fried" png's: http://www.jongware.com/pngdefry.html
  var pngFriedChunkName = 'CgBI'; 

  function isPNG (buffer) {
    if (pngSignature === buffer.toString('ascii', 1, 8)) {
      var chunkName = buffer.toString('ascii', 12, 16);
      if (chunkName === pngFriedChunkName) {
        chunkName = buffer.toString('ascii', 28, 32);
      }
      if (chunkName !== pngImageHeaderChunkName) {
        throw new TypeError('invalid png');
      }
      return true;
    }
  }

  function calculate$6 (buffer) {
    if (buffer.toString('ascii', 12, 16) === pngFriedChunkName) {
      return {
        'width': buffer.readUInt32BE(32),
        'height': buffer.readUInt32BE(36)
      };
    }
    return {
      'width': buffer.readUInt32BE(16),
      'height': buffer.readUInt32BE(20)
    };
  }

  var png = {
    'detect': isPNG,
    'calculate': calculate$6
  };

  function isPSD (buffer) {
    return ('8BPS' === buffer.toString('ascii', 0, 4));
  }

  function calculate$7 (buffer) {
    return {
      'width': buffer.readUInt32BE(18),
      'height': buffer.readUInt32BE(14)
    };
  }

  var psd = {
    'detect': isPSD,
    'calculate': calculate$7
  };

  var svgReg = /<svg\s([^>"']|"[^"]*"|'[^']*')*>/;
  function isSVG (buffer) {
    return svgReg.test(buffer);
  }

  var extractorRegExps = {
    'root': svgReg,
    'width': /\swidth=(['"])([^%]+?)\1/,
    'height': /\sheight=(['"])([^%]+?)\1/,
    'viewbox': /\sviewBox=(['"])(.+?)\1/
  };

  var units = {
    'cm': 96/2.54,
    'mm': 96/2.54/10,
    'm':  96/2.54*100,
    'pt': 96/72,
    'pc': 96/72/12,
    'em': 16,
    'ex': 8,
  };

  function parseLength (len) {
    var m = /([0-9.]+)([a-z]*)/.exec(len);
    if (!m) {
      return undefined;
    }
    return Math.round(parseFloat(m[1]) * (units[m[2]] || 1));
  }

  function parseViewbox (viewbox) {
    var bounds = viewbox.split(' ');
    return {
      'width': parseLength(bounds[2]),
      'height': parseLength(bounds[3])
    };
  }

  function parseAttributes (root) {
    var width = root.match(extractorRegExps.width);
    var height = root.match(extractorRegExps.height);
    var viewbox = root.match(extractorRegExps.viewbox);
    return {
      'width': width && parseLength(width[2]),
      'height': height && parseLength(height[2]),
      'viewbox': viewbox && parseViewbox(viewbox[2])
    };
  }

  function calculateByDimensions (attrs) {
    return {
      'width': attrs.width,
      'height': attrs.height
    };
  }

  function calculateByViewbox (attrs) {
    var ratio = attrs.viewbox.width / attrs.viewbox.height;
    if (attrs.width) {
      return {
        'width': attrs.width,
        'height': Math.floor(attrs.width / ratio)
      };
    }
    if (attrs.height) {
      return {
        'width': Math.floor(attrs.height * ratio),
        'height': attrs.height
      };
    }
    return {
      'width': attrs.viewbox.width,
      'height': attrs.viewbox.height
    };
  }

  function calculate$8 (buffer) {
    var root = buffer.toString('utf8').match(extractorRegExps.root);
    if (root) {
      var attrs = parseAttributes(root[0]);
      if (attrs.width && attrs.height) {
        return calculateByDimensions(attrs);
      }
      if (attrs.viewbox) {
        return calculateByViewbox(attrs);
      }
    }
    throw new TypeError('invalid svg');
  }

  var svg = {
    'detect': isSVG,
    'calculate': calculate$8
  };

  // based on http://www.compix.com/fileformattif.htm
  // TO-DO: support big-endian as well




  function isTIFF (buffer) {
    var hex4 = buffer.toString('hex', 0, 4);
    return ('49492a00' === hex4 || '4d4d002a' === hex4);
  }

  // Read IFD (image-file-directory) into a buffer
  function readIFD (buffer, filepath, isBigEndian) {

    var ifdOffset = readUInt_1(buffer, 32, 4, isBigEndian);

    // read only till the end of the file
    var bufferSize = 1024;
    var fileSize = fs__default['default'].statSync(filepath).size;
    if (ifdOffset + bufferSize > fileSize) {
      bufferSize = fileSize - ifdOffset - 10;
    }

    // populate the buffer
    var endBuffer = Buffer.alloc(bufferSize);
    var descriptor = fs__default['default'].openSync(filepath, 'r');
    fs__default['default'].readSync(descriptor, endBuffer, 0, bufferSize, ifdOffset);

    // var ifdLength = readUInt(endBuffer, 16, 0, isBigEndian);
    var ifdBuffer = endBuffer.slice(2); //, 2 + 12 * ifdLength);
    return ifdBuffer;
  }

  // TIFF values seem to be messed up on Big-Endian, this helps
  function readValue (buffer, isBigEndian) {
    var low = readUInt_1(buffer, 16, 8, isBigEndian);
    var high = readUInt_1(buffer, 16, 10, isBigEndian);
    return (high << 16) + low;
  }

  // move to the next tag
  function nextTag (buffer) {
    if (buffer.length > 24) {
      return buffer.slice(12);
    }
  }

  // Extract IFD tags from TIFF metadata
  /* eslint-disable complexity */
  function extractTags (buffer, isBigEndian) {
    var tags = {};
    var code, type, length;

    while (buffer && buffer.length) {
      code = readUInt_1(buffer, 16, 0, isBigEndian);
      type = readUInt_1(buffer, 16, 2, isBigEndian);
      length = readUInt_1(buffer, 32, 4, isBigEndian);

      // 0 means end of IFD
      if (code === 0) {
        break;
      } else {
        // 256 is width, 257 is height
        // if (code === 256 || code === 257) {
        if (length === 1 && (type === 3 || type === 4)) {
          tags[code] = readValue(buffer, isBigEndian);
        }

        // move to the next tag
        buffer = nextTag(buffer);
      }
    }
    return tags;
  }
  /* eslint-enable complexity */

  // Test if the TIFF is Big Endian or Little Endian
  function determineEndianness (buffer) {
    var signature = buffer.toString('ascii', 0, 2);
    if ('II' === signature) {
      return 'LE';
    } else if ('MM' === signature) {
      return 'BE';
    }
  }

  function calculate$9 (buffer, filepath) {

    if (!filepath) {
      throw new TypeError('Tiff doesn\'t support buffer');
    }

    // Determine BE/LE
    var isBigEndian = determineEndianness(buffer) === 'BE';

    // read the IFD
    var ifdBuffer = readIFD(buffer, filepath, isBigEndian);

    // extract the tags from the IFD
    var tags = extractTags(ifdBuffer, isBigEndian);

    var width = tags[256];
    var height = tags[257];

    if (!width || !height) {
      throw new TypeError('Invalid Tiff, missing tags');
    }

    return {
      'width': width,
      'height': height
    };
  }

  var tiff = {
    'detect': isTIFF,
    'calculate': calculate$9
  };

  // based on https://developers.google.com/speed/webp/docs/riff_container

  function isWebP (buffer) {
    var riffHeader = 'RIFF' === buffer.toString('ascii', 0, 4);
    var webpHeader = 'WEBP' === buffer.toString('ascii', 8, 12);
    var vp8Header  = 'VP8'  === buffer.toString('ascii', 12, 15);
    return (riffHeader && webpHeader && vp8Header);
  }

  /* eslint-disable complexity */
  function calculate$a (buffer) {
    var chunkHeader = buffer.toString('ascii', 12, 16);
    buffer = buffer.slice(20, 30);

    // Extended webp stream signature
    if (chunkHeader === 'VP8X') {
      var extendedHeader = buffer[0];
      var validStart = (extendedHeader & 0xc0) === 0;
      var validEnd = (extendedHeader & 0x01) === 0;
      if (validStart && validEnd) {
        return calculateExtended(buffer);
      } else {
        return false;
      }
    }

    // Lossless webp stream signature
    if (chunkHeader === 'VP8 ' && buffer[0] !== 0x2f) {
      return calculateLossy(buffer);
    }

    // Lossy webp stream signature
    var signature = buffer.toString('hex', 3, 6);
    if (chunkHeader === 'VP8L' && signature !== '9d012a') {
      return calculateLossless(buffer);
    }

    return false;
  }
  /* eslint-enable complexity */

  function calculateExtended (buffer) {
    return {
      'width': 1 + buffer.readUIntLE(4, 3),
      'height': 1 + buffer.readUIntLE(7, 3)
    };
  }

  function calculateLossless (buffer) {
    return {
      'width': 1 + (((buffer[2] & 0x3F) << 8) | buffer[1]),
      'height': 1 + (((buffer[4] & 0xF) << 10) | (buffer[3] << 2) |
                    ((buffer[2] & 0xC0) >> 6))
    };
  }

  function calculateLossy (buffer) {
    // `& 0x3fff` returns the last 14 bits
    // TO-DO: include webp scaling in the calculations
    return {
      'width': buffer.readInt16LE(6) & 0x3fff,
      'height': buffer.readInt16LE(8) & 0x3fff
    };
  }

  var webp = {
    'detect': isWebP,
    'calculate': calculate$a
  };

  // load all available handlers for browserify support
  var typeHandlers = {
    bmp: bmp,
    cur: cur,
    dds: dds,
    gif: gif,
    icns: icns,
    ico: ico,
    jpg: jpg,
    png: png,
    psd: psd,
    svg: svg,
    tiff: tiff,
    webp: webp,
  };

  var types = typeHandlers;

  var detector = function (buffer, filepath) {
    var type, result;
    for (type in types) {
      result = types[type].detect(buffer, filepath);
      if (result) {
        return type;
      }
    }
  };

  // Maximum buffer size, with a default of 512 kilobytes.
  // TO-DO: make this adaptive based on the initial signature of the image
  var MaxBufferSize = 512*1024;

  /**
   * Return size information based on a buffer
   *
   * @param {Buffer} buffer
   * @param {String} filepath
   * @returns {Object}
   */
  function lookup (buffer, filepath) {
    // detect the file type.. don't rely on the extension
    var type = detector(buffer, filepath);

    // find an appropriate handler for this file type
    if (type in types) {
      var size = types[type].calculate(buffer, filepath);
      if (size !== false) {
        size.type = type;
        return size;
      }
    }

    // throw up, if we don't understand the file
    throw new TypeError('unsupported file type: ' + type + ' (file: ' + filepath + ')');
  }

  /**
   * Reads a file into a buffer.
   *
   * The callback will be called after the process has completed. The
   * callback's first argument will be an error (or null). The second argument
   * will be the Buffer, if the operation was successful.
   *
   * @param {String} filepath
   * @param {Function} callback
   */
  function asyncFileToBuffer (filepath, callback) {
    // open the file in read only mode
    fs__default['default'].open(filepath, 'r', function (err, descriptor) {
      if (err) { return callback(err); }
      fs__default['default'].fstat(descriptor, function (err, stats) {
        if (err) { return callback(err); }
        var size = stats.size;
        if (size <= 0) {
          return callback(new Error('File size is not greater than 0 —— ' + filepath));
        }
        var bufferSize = Math.min(size, MaxBufferSize);
        var buffer = Buffer.alloc(bufferSize);
        // read first buffer block from the file, asynchronously
        fs__default['default'].read(descriptor, buffer, 0, bufferSize, 0, function (err) {
          if (err) { return callback(err); }
          // close the file, we are done
          fs__default['default'].close(descriptor, function (err) {
            callback(err, buffer);
          });
        });
      });
    });
  }

  /**
   * Synchronously reads a file into a buffer, blocking the nodejs process.
   *
   * @param {String} filepath
   * @returns {Buffer}
   */
  function syncFileToBuffer (filepath) {
    // read from the file, synchronously
    var descriptor = fs__default['default'].openSync(filepath, 'r');
    var size = fs__default['default'].fstatSync(descriptor).size;
    var bufferSize = Math.min(size, MaxBufferSize);
    var buffer = Buffer.alloc(bufferSize);
    fs__default['default'].readSync(descriptor, buffer, 0, bufferSize, 0);
    fs__default['default'].closeSync(descriptor);
    return buffer;
  }

  /**
   * @param {Buffer|string} input - buffer or relative/absolute path of the image file
   * @param {Function=} callback - optional function for async detection
   */
  var lib = function (input, callback) {

    // Handle buffer input
    if (Buffer.isBuffer(input)) {
      return lookup(input);
    }

    // input should be a string at this point
    if (typeof input !== 'string') {
      throw new TypeError('invalid invocation');
    }

    // resolve the file path
    var filepath = path__default['default'].resolve(input);

    if (typeof callback === 'function') {
      asyncFileToBuffer(filepath, function (err, buffer) {
        if (err) { return callback(err); }

        // return the dimensions
        var dimensions;
        try {
          dimensions = lookup(buffer, filepath);
        } catch (e) {
          err = e;
        }
        callback(err, dimensions);
      });
    } else {
      var buffer = syncFileToBuffer(filepath);
      return lookup(buffer, filepath);
    }
  };

  var types$1 = Object.keys(types);
  lib.types = types$1;

  function createCommonjsModule(fn, basedir, module) {
  	return module = {
  	  path: basedir,
  	  exports: {},
  	  require: function (path, base) {
        return commonjsRequire(path, (base === undefined || base === null) ? module.path : base);
      }
  	}, fn(module, module.exports), module.exports;
  }

  function commonjsRequire () {
  	throw new Error('Dynamic requires are not currently supported by @rollup/plugin-commonjs');
  }

  var hasFlag = (flag, argv) => {
  	argv = argv || process.argv;
  	const prefix = flag.startsWith('-') ? '' : (flag.length === 1 ? '-' : '--');
  	const pos = argv.indexOf(prefix + flag);
  	const terminatorPos = argv.indexOf('--');
  	return pos !== -1 && (terminatorPos === -1 ? true : pos < terminatorPos);
  };

  const {env} = process;

  let forceColor;
  if (hasFlag('no-color') ||
  	hasFlag('no-colors') ||
  	hasFlag('color=false') ||
  	hasFlag('color=never')) {
  	forceColor = 0;
  } else if (hasFlag('color') ||
  	hasFlag('colors') ||
  	hasFlag('color=true') ||
  	hasFlag('color=always')) {
  	forceColor = 1;
  }
  if ('FORCE_COLOR' in env) {
  	if (env.FORCE_COLOR === true || env.FORCE_COLOR === 'true') {
  		forceColor = 1;
  	} else if (env.FORCE_COLOR === false || env.FORCE_COLOR === 'false') {
  		forceColor = 0;
  	} else {
  		forceColor = env.FORCE_COLOR.length === 0 ? 1 : Math.min(parseInt(env.FORCE_COLOR, 10), 3);
  	}
  }

  function translateLevel(level) {
  	if (level === 0) {
  		return false;
  	}

  	return {
  		level,
  		hasBasic: true,
  		has256: level >= 2,
  		has16m: level >= 3
  	};
  }

  function supportsColor(stream) {
  	if (forceColor === 0) {
  		return 0;
  	}

  	if (hasFlag('color=16m') ||
  		hasFlag('color=full') ||
  		hasFlag('color=truecolor')) {
  		return 3;
  	}

  	if (hasFlag('color=256')) {
  		return 2;
  	}

  	if (stream && !stream.isTTY && forceColor === undefined) {
  		return 0;
  	}

  	const min = forceColor || 0;

  	if (env.TERM === 'dumb') {
  		return min;
  	}

  	if (process.platform === 'win32') {
  		// Node.js 7.5.0 is the first version of Node.js to include a patch to
  		// libuv that enables 256 color output on Windows. Anything earlier and it
  		// won't work. However, here we target Node.js 8 at minimum as it is an LTS
  		// release, and Node.js 7 is not. Windows 10 build 10586 is the first Windows
  		// release that supports 256 colors. Windows 10 build 14931 is the first release
  		// that supports 16m/TrueColor.
  		const osRelease = os__default['default'].release().split('.');
  		if (
  			Number(process.versions.node.split('.')[0]) >= 8 &&
  			Number(osRelease[0]) >= 10 &&
  			Number(osRelease[2]) >= 10586
  		) {
  			return Number(osRelease[2]) >= 14931 ? 3 : 2;
  		}

  		return 1;
  	}

  	if ('CI' in env) {
  		if (['TRAVIS', 'CIRCLECI', 'APPVEYOR', 'GITLAB_CI'].some(sign => sign in env) || env.CI_NAME === 'codeship') {
  			return 1;
  		}

  		return min;
  	}

  	if ('TEAMCITY_VERSION' in env) {
  		return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(env.TEAMCITY_VERSION) ? 1 : 0;
  	}

  	if (env.COLORTERM === 'truecolor') {
  		return 3;
  	}

  	if ('TERM_PROGRAM' in env) {
  		const version = parseInt((env.TERM_PROGRAM_VERSION || '').split('.')[0], 10);

  		switch (env.TERM_PROGRAM) {
  			case 'iTerm.app':
  				return version >= 3 ? 3 : 2;
  			case 'Apple_Terminal':
  				return 2;
  			// No default
  		}
  	}

  	if (/-256(color)?$/i.test(env.TERM)) {
  		return 2;
  	}

  	if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(env.TERM)) {
  		return 1;
  	}

  	if ('COLORTERM' in env) {
  		return 1;
  	}

  	return min;
  }

  function getSupportLevel(stream) {
  	const level = supportsColor(stream);
  	return translateLevel(level);
  }

  var supportsColor_1 = {
  	supportsColor: getSupportLevel,
  	stdout: getSupportLevel(process.stdout),
  	stderr: getSupportLevel(process.stderr)
  };

  var matchOperatorsRe = /[|\\{}()[\]^$+*?.]/g;

  var escapeStringRegexp = function (str) {
  	if (typeof str !== 'string') {
  		throw new TypeError('Expected a string');
  	}

  	return str.replace(matchOperatorsRe, '\\$&');
  };

  var colorName = {
  	"aliceblue": [240, 248, 255],
  	"antiquewhite": [250, 235, 215],
  	"aqua": [0, 255, 255],
  	"aquamarine": [127, 255, 212],
  	"azure": [240, 255, 255],
  	"beige": [245, 245, 220],
  	"bisque": [255, 228, 196],
  	"black": [0, 0, 0],
  	"blanchedalmond": [255, 235, 205],
  	"blue": [0, 0, 255],
  	"blueviolet": [138, 43, 226],
  	"brown": [165, 42, 42],
  	"burlywood": [222, 184, 135],
  	"cadetblue": [95, 158, 160],
  	"chartreuse": [127, 255, 0],
  	"chocolate": [210, 105, 30],
  	"coral": [255, 127, 80],
  	"cornflowerblue": [100, 149, 237],
  	"cornsilk": [255, 248, 220],
  	"crimson": [220, 20, 60],
  	"cyan": [0, 255, 255],
  	"darkblue": [0, 0, 139],
  	"darkcyan": [0, 139, 139],
  	"darkgoldenrod": [184, 134, 11],
  	"darkgray": [169, 169, 169],
  	"darkgreen": [0, 100, 0],
  	"darkgrey": [169, 169, 169],
  	"darkkhaki": [189, 183, 107],
  	"darkmagenta": [139, 0, 139],
  	"darkolivegreen": [85, 107, 47],
  	"darkorange": [255, 140, 0],
  	"darkorchid": [153, 50, 204],
  	"darkred": [139, 0, 0],
  	"darksalmon": [233, 150, 122],
  	"darkseagreen": [143, 188, 143],
  	"darkslateblue": [72, 61, 139],
  	"darkslategray": [47, 79, 79],
  	"darkslategrey": [47, 79, 79],
  	"darkturquoise": [0, 206, 209],
  	"darkviolet": [148, 0, 211],
  	"deeppink": [255, 20, 147],
  	"deepskyblue": [0, 191, 255],
  	"dimgray": [105, 105, 105],
  	"dimgrey": [105, 105, 105],
  	"dodgerblue": [30, 144, 255],
  	"firebrick": [178, 34, 34],
  	"floralwhite": [255, 250, 240],
  	"forestgreen": [34, 139, 34],
  	"fuchsia": [255, 0, 255],
  	"gainsboro": [220, 220, 220],
  	"ghostwhite": [248, 248, 255],
  	"gold": [255, 215, 0],
  	"goldenrod": [218, 165, 32],
  	"gray": [128, 128, 128],
  	"green": [0, 128, 0],
  	"greenyellow": [173, 255, 47],
  	"grey": [128, 128, 128],
  	"honeydew": [240, 255, 240],
  	"hotpink": [255, 105, 180],
  	"indianred": [205, 92, 92],
  	"indigo": [75, 0, 130],
  	"ivory": [255, 255, 240],
  	"khaki": [240, 230, 140],
  	"lavender": [230, 230, 250],
  	"lavenderblush": [255, 240, 245],
  	"lawngreen": [124, 252, 0],
  	"lemonchiffon": [255, 250, 205],
  	"lightblue": [173, 216, 230],
  	"lightcoral": [240, 128, 128],
  	"lightcyan": [224, 255, 255],
  	"lightgoldenrodyellow": [250, 250, 210],
  	"lightgray": [211, 211, 211],
  	"lightgreen": [144, 238, 144],
  	"lightgrey": [211, 211, 211],
  	"lightpink": [255, 182, 193],
  	"lightsalmon": [255, 160, 122],
  	"lightseagreen": [32, 178, 170],
  	"lightskyblue": [135, 206, 250],
  	"lightslategray": [119, 136, 153],
  	"lightslategrey": [119, 136, 153],
  	"lightsteelblue": [176, 196, 222],
  	"lightyellow": [255, 255, 224],
  	"lime": [0, 255, 0],
  	"limegreen": [50, 205, 50],
  	"linen": [250, 240, 230],
  	"magenta": [255, 0, 255],
  	"maroon": [128, 0, 0],
  	"mediumaquamarine": [102, 205, 170],
  	"mediumblue": [0, 0, 205],
  	"mediumorchid": [186, 85, 211],
  	"mediumpurple": [147, 112, 219],
  	"mediumseagreen": [60, 179, 113],
  	"mediumslateblue": [123, 104, 238],
  	"mediumspringgreen": [0, 250, 154],
  	"mediumturquoise": [72, 209, 204],
  	"mediumvioletred": [199, 21, 133],
  	"midnightblue": [25, 25, 112],
  	"mintcream": [245, 255, 250],
  	"mistyrose": [255, 228, 225],
  	"moccasin": [255, 228, 181],
  	"navajowhite": [255, 222, 173],
  	"navy": [0, 0, 128],
  	"oldlace": [253, 245, 230],
  	"olive": [128, 128, 0],
  	"olivedrab": [107, 142, 35],
  	"orange": [255, 165, 0],
  	"orangered": [255, 69, 0],
  	"orchid": [218, 112, 214],
  	"palegoldenrod": [238, 232, 170],
  	"palegreen": [152, 251, 152],
  	"paleturquoise": [175, 238, 238],
  	"palevioletred": [219, 112, 147],
  	"papayawhip": [255, 239, 213],
  	"peachpuff": [255, 218, 185],
  	"peru": [205, 133, 63],
  	"pink": [255, 192, 203],
  	"plum": [221, 160, 221],
  	"powderblue": [176, 224, 230],
  	"purple": [128, 0, 128],
  	"rebeccapurple": [102, 51, 153],
  	"red": [255, 0, 0],
  	"rosybrown": [188, 143, 143],
  	"royalblue": [65, 105, 225],
  	"saddlebrown": [139, 69, 19],
  	"salmon": [250, 128, 114],
  	"sandybrown": [244, 164, 96],
  	"seagreen": [46, 139, 87],
  	"seashell": [255, 245, 238],
  	"sienna": [160, 82, 45],
  	"silver": [192, 192, 192],
  	"skyblue": [135, 206, 235],
  	"slateblue": [106, 90, 205],
  	"slategray": [112, 128, 144],
  	"slategrey": [112, 128, 144],
  	"snow": [255, 250, 250],
  	"springgreen": [0, 255, 127],
  	"steelblue": [70, 130, 180],
  	"tan": [210, 180, 140],
  	"teal": [0, 128, 128],
  	"thistle": [216, 191, 216],
  	"tomato": [255, 99, 71],
  	"turquoise": [64, 224, 208],
  	"violet": [238, 130, 238],
  	"wheat": [245, 222, 179],
  	"white": [255, 255, 255],
  	"whitesmoke": [245, 245, 245],
  	"yellow": [255, 255, 0],
  	"yellowgreen": [154, 205, 50]
  };

  var conversions = createCommonjsModule(function (module) {
  /* MIT license */


  // NOTE: conversions should only return primitive values (i.e. arrays, or
  //       values that give correct `typeof` results).
  //       do not use box values types (i.e. Number(), String(), etc.)

  var reverseKeywords = {};
  for (var key in colorName) {
  	if (colorName.hasOwnProperty(key)) {
  		reverseKeywords[colorName[key]] = key;
  	}
  }

  var convert = module.exports = {
  	rgb: {channels: 3, labels: 'rgb'},
  	hsl: {channels: 3, labels: 'hsl'},
  	hsv: {channels: 3, labels: 'hsv'},
  	hwb: {channels: 3, labels: 'hwb'},
  	cmyk: {channels: 4, labels: 'cmyk'},
  	xyz: {channels: 3, labels: 'xyz'},
  	lab: {channels: 3, labels: 'lab'},
  	lch: {channels: 3, labels: 'lch'},
  	hex: {channels: 1, labels: ['hex']},
  	keyword: {channels: 1, labels: ['keyword']},
  	ansi16: {channels: 1, labels: ['ansi16']},
  	ansi256: {channels: 1, labels: ['ansi256']},
  	hcg: {channels: 3, labels: ['h', 'c', 'g']},
  	apple: {channels: 3, labels: ['r16', 'g16', 'b16']},
  	gray: {channels: 1, labels: ['gray']}
  };

  // hide .channels and .labels properties
  for (var model in convert) {
  	if (convert.hasOwnProperty(model)) {
  		if (!('channels' in convert[model])) {
  			throw new Error('missing channels property: ' + model);
  		}

  		if (!('labels' in convert[model])) {
  			throw new Error('missing channel labels property: ' + model);
  		}

  		if (convert[model].labels.length !== convert[model].channels) {
  			throw new Error('channel and label counts mismatch: ' + model);
  		}

  		var channels = convert[model].channels;
  		var labels = convert[model].labels;
  		delete convert[model].channels;
  		delete convert[model].labels;
  		Object.defineProperty(convert[model], 'channels', {value: channels});
  		Object.defineProperty(convert[model], 'labels', {value: labels});
  	}
  }

  convert.rgb.hsl = function (rgb) {
  	var r = rgb[0] / 255;
  	var g = rgb[1] / 255;
  	var b = rgb[2] / 255;
  	var min = Math.min(r, g, b);
  	var max = Math.max(r, g, b);
  	var delta = max - min;
  	var h;
  	var s;
  	var l;

  	if (max === min) {
  		h = 0;
  	} else if (r === max) {
  		h = (g - b) / delta;
  	} else if (g === max) {
  		h = 2 + (b - r) / delta;
  	} else if (b === max) {
  		h = 4 + (r - g) / delta;
  	}

  	h = Math.min(h * 60, 360);

  	if (h < 0) {
  		h += 360;
  	}

  	l = (min + max) / 2;

  	if (max === min) {
  		s = 0;
  	} else if (l <= 0.5) {
  		s = delta / (max + min);
  	} else {
  		s = delta / (2 - max - min);
  	}

  	return [h, s * 100, l * 100];
  };

  convert.rgb.hsv = function (rgb) {
  	var rdif;
  	var gdif;
  	var bdif;
  	var h;
  	var s;

  	var r = rgb[0] / 255;
  	var g = rgb[1] / 255;
  	var b = rgb[2] / 255;
  	var v = Math.max(r, g, b);
  	var diff = v - Math.min(r, g, b);
  	var diffc = function (c) {
  		return (v - c) / 6 / diff + 1 / 2;
  	};

  	if (diff === 0) {
  		h = s = 0;
  	} else {
  		s = diff / v;
  		rdif = diffc(r);
  		gdif = diffc(g);
  		bdif = diffc(b);

  		if (r === v) {
  			h = bdif - gdif;
  		} else if (g === v) {
  			h = (1 / 3) + rdif - bdif;
  		} else if (b === v) {
  			h = (2 / 3) + gdif - rdif;
  		}
  		if (h < 0) {
  			h += 1;
  		} else if (h > 1) {
  			h -= 1;
  		}
  	}

  	return [
  		h * 360,
  		s * 100,
  		v * 100
  	];
  };

  convert.rgb.hwb = function (rgb) {
  	var r = rgb[0];
  	var g = rgb[1];
  	var b = rgb[2];
  	var h = convert.rgb.hsl(rgb)[0];
  	var w = 1 / 255 * Math.min(r, Math.min(g, b));

  	b = 1 - 1 / 255 * Math.max(r, Math.max(g, b));

  	return [h, w * 100, b * 100];
  };

  convert.rgb.cmyk = function (rgb) {
  	var r = rgb[0] / 255;
  	var g = rgb[1] / 255;
  	var b = rgb[2] / 255;
  	var c;
  	var m;
  	var y;
  	var k;

  	k = Math.min(1 - r, 1 - g, 1 - b);
  	c = (1 - r - k) / (1 - k) || 0;
  	m = (1 - g - k) / (1 - k) || 0;
  	y = (1 - b - k) / (1 - k) || 0;

  	return [c * 100, m * 100, y * 100, k * 100];
  };

  /**
   * See https://en.m.wikipedia.org/wiki/Euclidean_distance#Squared_Euclidean_distance
   * */
  function comparativeDistance(x, y) {
  	return (
  		Math.pow(x[0] - y[0], 2) +
  		Math.pow(x[1] - y[1], 2) +
  		Math.pow(x[2] - y[2], 2)
  	);
  }

  convert.rgb.keyword = function (rgb) {
  	var reversed = reverseKeywords[rgb];
  	if (reversed) {
  		return reversed;
  	}

  	var currentClosestDistance = Infinity;
  	var currentClosestKeyword;

  	for (var keyword in colorName) {
  		if (colorName.hasOwnProperty(keyword)) {
  			var value = colorName[keyword];

  			// Compute comparative distance
  			var distance = comparativeDistance(rgb, value);

  			// Check if its less, if so set as closest
  			if (distance < currentClosestDistance) {
  				currentClosestDistance = distance;
  				currentClosestKeyword = keyword;
  			}
  		}
  	}

  	return currentClosestKeyword;
  };

  convert.keyword.rgb = function (keyword) {
  	return colorName[keyword];
  };

  convert.rgb.xyz = function (rgb) {
  	var r = rgb[0] / 255;
  	var g = rgb[1] / 255;
  	var b = rgb[2] / 255;

  	// assume sRGB
  	r = r > 0.04045 ? Math.pow(((r + 0.055) / 1.055), 2.4) : (r / 12.92);
  	g = g > 0.04045 ? Math.pow(((g + 0.055) / 1.055), 2.4) : (g / 12.92);
  	b = b > 0.04045 ? Math.pow(((b + 0.055) / 1.055), 2.4) : (b / 12.92);

  	var x = (r * 0.4124) + (g * 0.3576) + (b * 0.1805);
  	var y = (r * 0.2126) + (g * 0.7152) + (b * 0.0722);
  	var z = (r * 0.0193) + (g * 0.1192) + (b * 0.9505);

  	return [x * 100, y * 100, z * 100];
  };

  convert.rgb.lab = function (rgb) {
  	var xyz = convert.rgb.xyz(rgb);
  	var x = xyz[0];
  	var y = xyz[1];
  	var z = xyz[2];
  	var l;
  	var a;
  	var b;

  	x /= 95.047;
  	y /= 100;
  	z /= 108.883;

  	x = x > 0.008856 ? Math.pow(x, 1 / 3) : (7.787 * x) + (16 / 116);
  	y = y > 0.008856 ? Math.pow(y, 1 / 3) : (7.787 * y) + (16 / 116);
  	z = z > 0.008856 ? Math.pow(z, 1 / 3) : (7.787 * z) + (16 / 116);

  	l = (116 * y) - 16;
  	a = 500 * (x - y);
  	b = 200 * (y - z);

  	return [l, a, b];
  };

  convert.hsl.rgb = function (hsl) {
  	var h = hsl[0] / 360;
  	var s = hsl[1] / 100;
  	var l = hsl[2] / 100;
  	var t1;
  	var t2;
  	var t3;
  	var rgb;
  	var val;

  	if (s === 0) {
  		val = l * 255;
  		return [val, val, val];
  	}

  	if (l < 0.5) {
  		t2 = l * (1 + s);
  	} else {
  		t2 = l + s - l * s;
  	}

  	t1 = 2 * l - t2;

  	rgb = [0, 0, 0];
  	for (var i = 0; i < 3; i++) {
  		t3 = h + 1 / 3 * -(i - 1);
  		if (t3 < 0) {
  			t3++;
  		}
  		if (t3 > 1) {
  			t3--;
  		}

  		if (6 * t3 < 1) {
  			val = t1 + (t2 - t1) * 6 * t3;
  		} else if (2 * t3 < 1) {
  			val = t2;
  		} else if (3 * t3 < 2) {
  			val = t1 + (t2 - t1) * (2 / 3 - t3) * 6;
  		} else {
  			val = t1;
  		}

  		rgb[i] = val * 255;
  	}

  	return rgb;
  };

  convert.hsl.hsv = function (hsl) {
  	var h = hsl[0];
  	var s = hsl[1] / 100;
  	var l = hsl[2] / 100;
  	var smin = s;
  	var lmin = Math.max(l, 0.01);
  	var sv;
  	var v;

  	l *= 2;
  	s *= (l <= 1) ? l : 2 - l;
  	smin *= lmin <= 1 ? lmin : 2 - lmin;
  	v = (l + s) / 2;
  	sv = l === 0 ? (2 * smin) / (lmin + smin) : (2 * s) / (l + s);

  	return [h, sv * 100, v * 100];
  };

  convert.hsv.rgb = function (hsv) {
  	var h = hsv[0] / 60;
  	var s = hsv[1] / 100;
  	var v = hsv[2] / 100;
  	var hi = Math.floor(h) % 6;

  	var f = h - Math.floor(h);
  	var p = 255 * v * (1 - s);
  	var q = 255 * v * (1 - (s * f));
  	var t = 255 * v * (1 - (s * (1 - f)));
  	v *= 255;

  	switch (hi) {
  		case 0:
  			return [v, t, p];
  		case 1:
  			return [q, v, p];
  		case 2:
  			return [p, v, t];
  		case 3:
  			return [p, q, v];
  		case 4:
  			return [t, p, v];
  		case 5:
  			return [v, p, q];
  	}
  };

  convert.hsv.hsl = function (hsv) {
  	var h = hsv[0];
  	var s = hsv[1] / 100;
  	var v = hsv[2] / 100;
  	var vmin = Math.max(v, 0.01);
  	var lmin;
  	var sl;
  	var l;

  	l = (2 - s) * v;
  	lmin = (2 - s) * vmin;
  	sl = s * vmin;
  	sl /= (lmin <= 1) ? lmin : 2 - lmin;
  	sl = sl || 0;
  	l /= 2;

  	return [h, sl * 100, l * 100];
  };

  // http://dev.w3.org/csswg/css-color/#hwb-to-rgb
  convert.hwb.rgb = function (hwb) {
  	var h = hwb[0] / 360;
  	var wh = hwb[1] / 100;
  	var bl = hwb[2] / 100;
  	var ratio = wh + bl;
  	var i;
  	var v;
  	var f;
  	var n;

  	// wh + bl cant be > 1
  	if (ratio > 1) {
  		wh /= ratio;
  		bl /= ratio;
  	}

  	i = Math.floor(6 * h);
  	v = 1 - bl;
  	f = 6 * h - i;

  	if ((i & 0x01) !== 0) {
  		f = 1 - f;
  	}

  	n = wh + f * (v - wh); // linear interpolation

  	var r;
  	var g;
  	var b;
  	switch (i) {
  		default:
  		case 6:
  		case 0: r = v; g = n; b = wh; break;
  		case 1: r = n; g = v; b = wh; break;
  		case 2: r = wh; g = v; b = n; break;
  		case 3: r = wh; g = n; b = v; break;
  		case 4: r = n; g = wh; b = v; break;
  		case 5: r = v; g = wh; b = n; break;
  	}

  	return [r * 255, g * 255, b * 255];
  };

  convert.cmyk.rgb = function (cmyk) {
  	var c = cmyk[0] / 100;
  	var m = cmyk[1] / 100;
  	var y = cmyk[2] / 100;
  	var k = cmyk[3] / 100;
  	var r;
  	var g;
  	var b;

  	r = 1 - Math.min(1, c * (1 - k) + k);
  	g = 1 - Math.min(1, m * (1 - k) + k);
  	b = 1 - Math.min(1, y * (1 - k) + k);

  	return [r * 255, g * 255, b * 255];
  };

  convert.xyz.rgb = function (xyz) {
  	var x = xyz[0] / 100;
  	var y = xyz[1] / 100;
  	var z = xyz[2] / 100;
  	var r;
  	var g;
  	var b;

  	r = (x * 3.2406) + (y * -1.5372) + (z * -0.4986);
  	g = (x * -0.9689) + (y * 1.8758) + (z * 0.0415);
  	b = (x * 0.0557) + (y * -0.2040) + (z * 1.0570);

  	// assume sRGB
  	r = r > 0.0031308
  		? ((1.055 * Math.pow(r, 1.0 / 2.4)) - 0.055)
  		: r * 12.92;

  	g = g > 0.0031308
  		? ((1.055 * Math.pow(g, 1.0 / 2.4)) - 0.055)
  		: g * 12.92;

  	b = b > 0.0031308
  		? ((1.055 * Math.pow(b, 1.0 / 2.4)) - 0.055)
  		: b * 12.92;

  	r = Math.min(Math.max(0, r), 1);
  	g = Math.min(Math.max(0, g), 1);
  	b = Math.min(Math.max(0, b), 1);

  	return [r * 255, g * 255, b * 255];
  };

  convert.xyz.lab = function (xyz) {
  	var x = xyz[0];
  	var y = xyz[1];
  	var z = xyz[2];
  	var l;
  	var a;
  	var b;

  	x /= 95.047;
  	y /= 100;
  	z /= 108.883;

  	x = x > 0.008856 ? Math.pow(x, 1 / 3) : (7.787 * x) + (16 / 116);
  	y = y > 0.008856 ? Math.pow(y, 1 / 3) : (7.787 * y) + (16 / 116);
  	z = z > 0.008856 ? Math.pow(z, 1 / 3) : (7.787 * z) + (16 / 116);

  	l = (116 * y) - 16;
  	a = 500 * (x - y);
  	b = 200 * (y - z);

  	return [l, a, b];
  };

  convert.lab.xyz = function (lab) {
  	var l = lab[0];
  	var a = lab[1];
  	var b = lab[2];
  	var x;
  	var y;
  	var z;

  	y = (l + 16) / 116;
  	x = a / 500 + y;
  	z = y - b / 200;

  	var y2 = Math.pow(y, 3);
  	var x2 = Math.pow(x, 3);
  	var z2 = Math.pow(z, 3);
  	y = y2 > 0.008856 ? y2 : (y - 16 / 116) / 7.787;
  	x = x2 > 0.008856 ? x2 : (x - 16 / 116) / 7.787;
  	z = z2 > 0.008856 ? z2 : (z - 16 / 116) / 7.787;

  	x *= 95.047;
  	y *= 100;
  	z *= 108.883;

  	return [x, y, z];
  };

  convert.lab.lch = function (lab) {
  	var l = lab[0];
  	var a = lab[1];
  	var b = lab[2];
  	var hr;
  	var h;
  	var c;

  	hr = Math.atan2(b, a);
  	h = hr * 360 / 2 / Math.PI;

  	if (h < 0) {
  		h += 360;
  	}

  	c = Math.sqrt(a * a + b * b);

  	return [l, c, h];
  };

  convert.lch.lab = function (lch) {
  	var l = lch[0];
  	var c = lch[1];
  	var h = lch[2];
  	var a;
  	var b;
  	var hr;

  	hr = h / 360 * 2 * Math.PI;
  	a = c * Math.cos(hr);
  	b = c * Math.sin(hr);

  	return [l, a, b];
  };

  convert.rgb.ansi16 = function (args) {
  	var r = args[0];
  	var g = args[1];
  	var b = args[2];
  	var value = 1 in arguments ? arguments[1] : convert.rgb.hsv(args)[2]; // hsv -> ansi16 optimization

  	value = Math.round(value / 50);

  	if (value === 0) {
  		return 30;
  	}

  	var ansi = 30
  		+ ((Math.round(b / 255) << 2)
  		| (Math.round(g / 255) << 1)
  		| Math.round(r / 255));

  	if (value === 2) {
  		ansi += 60;
  	}

  	return ansi;
  };

  convert.hsv.ansi16 = function (args) {
  	// optimization here; we already know the value and don't need to get
  	// it converted for us.
  	return convert.rgb.ansi16(convert.hsv.rgb(args), args[2]);
  };

  convert.rgb.ansi256 = function (args) {
  	var r = args[0];
  	var g = args[1];
  	var b = args[2];

  	// we use the extended greyscale palette here, with the exception of
  	// black and white. normal palette only has 4 greyscale shades.
  	if (r === g && g === b) {
  		if (r < 8) {
  			return 16;
  		}

  		if (r > 248) {
  			return 231;
  		}

  		return Math.round(((r - 8) / 247) * 24) + 232;
  	}

  	var ansi = 16
  		+ (36 * Math.round(r / 255 * 5))
  		+ (6 * Math.round(g / 255 * 5))
  		+ Math.round(b / 255 * 5);

  	return ansi;
  };

  convert.ansi16.rgb = function (args) {
  	var color = args % 10;

  	// handle greyscale
  	if (color === 0 || color === 7) {
  		if (args > 50) {
  			color += 3.5;
  		}

  		color = color / 10.5 * 255;

  		return [color, color, color];
  	}

  	var mult = (~~(args > 50) + 1) * 0.5;
  	var r = ((color & 1) * mult) * 255;
  	var g = (((color >> 1) & 1) * mult) * 255;
  	var b = (((color >> 2) & 1) * mult) * 255;

  	return [r, g, b];
  };

  convert.ansi256.rgb = function (args) {
  	// handle greyscale
  	if (args >= 232) {
  		var c = (args - 232) * 10 + 8;
  		return [c, c, c];
  	}

  	args -= 16;

  	var rem;
  	var r = Math.floor(args / 36) / 5 * 255;
  	var g = Math.floor((rem = args % 36) / 6) / 5 * 255;
  	var b = (rem % 6) / 5 * 255;

  	return [r, g, b];
  };

  convert.rgb.hex = function (args) {
  	var integer = ((Math.round(args[0]) & 0xFF) << 16)
  		+ ((Math.round(args[1]) & 0xFF) << 8)
  		+ (Math.round(args[2]) & 0xFF);

  	var string = integer.toString(16).toUpperCase();
  	return '000000'.substring(string.length) + string;
  };

  convert.hex.rgb = function (args) {
  	var match = args.toString(16).match(/[a-f0-9]{6}|[a-f0-9]{3}/i);
  	if (!match) {
  		return [0, 0, 0];
  	}

  	var colorString = match[0];

  	if (match[0].length === 3) {
  		colorString = colorString.split('').map(function (char) {
  			return char + char;
  		}).join('');
  	}

  	var integer = parseInt(colorString, 16);
  	var r = (integer >> 16) & 0xFF;
  	var g = (integer >> 8) & 0xFF;
  	var b = integer & 0xFF;

  	return [r, g, b];
  };

  convert.rgb.hcg = function (rgb) {
  	var r = rgb[0] / 255;
  	var g = rgb[1] / 255;
  	var b = rgb[2] / 255;
  	var max = Math.max(Math.max(r, g), b);
  	var min = Math.min(Math.min(r, g), b);
  	var chroma = (max - min);
  	var grayscale;
  	var hue;

  	if (chroma < 1) {
  		grayscale = min / (1 - chroma);
  	} else {
  		grayscale = 0;
  	}

  	if (chroma <= 0) {
  		hue = 0;
  	} else
  	if (max === r) {
  		hue = ((g - b) / chroma) % 6;
  	} else
  	if (max === g) {
  		hue = 2 + (b - r) / chroma;
  	} else {
  		hue = 4 + (r - g) / chroma + 4;
  	}

  	hue /= 6;
  	hue %= 1;

  	return [hue * 360, chroma * 100, grayscale * 100];
  };

  convert.hsl.hcg = function (hsl) {
  	var s = hsl[1] / 100;
  	var l = hsl[2] / 100;
  	var c = 1;
  	var f = 0;

  	if (l < 0.5) {
  		c = 2.0 * s * l;
  	} else {
  		c = 2.0 * s * (1.0 - l);
  	}

  	if (c < 1.0) {
  		f = (l - 0.5 * c) / (1.0 - c);
  	}

  	return [hsl[0], c * 100, f * 100];
  };

  convert.hsv.hcg = function (hsv) {
  	var s = hsv[1] / 100;
  	var v = hsv[2] / 100;

  	var c = s * v;
  	var f = 0;

  	if (c < 1.0) {
  		f = (v - c) / (1 - c);
  	}

  	return [hsv[0], c * 100, f * 100];
  };

  convert.hcg.rgb = function (hcg) {
  	var h = hcg[0] / 360;
  	var c = hcg[1] / 100;
  	var g = hcg[2] / 100;

  	if (c === 0.0) {
  		return [g * 255, g * 255, g * 255];
  	}

  	var pure = [0, 0, 0];
  	var hi = (h % 1) * 6;
  	var v = hi % 1;
  	var w = 1 - v;
  	var mg = 0;

  	switch (Math.floor(hi)) {
  		case 0:
  			pure[0] = 1; pure[1] = v; pure[2] = 0; break;
  		case 1:
  			pure[0] = w; pure[1] = 1; pure[2] = 0; break;
  		case 2:
  			pure[0] = 0; pure[1] = 1; pure[2] = v; break;
  		case 3:
  			pure[0] = 0; pure[1] = w; pure[2] = 1; break;
  		case 4:
  			pure[0] = v; pure[1] = 0; pure[2] = 1; break;
  		default:
  			pure[0] = 1; pure[1] = 0; pure[2] = w;
  	}

  	mg = (1.0 - c) * g;

  	return [
  		(c * pure[0] + mg) * 255,
  		(c * pure[1] + mg) * 255,
  		(c * pure[2] + mg) * 255
  	];
  };

  convert.hcg.hsv = function (hcg) {
  	var c = hcg[1] / 100;
  	var g = hcg[2] / 100;

  	var v = c + g * (1.0 - c);
  	var f = 0;

  	if (v > 0.0) {
  		f = c / v;
  	}

  	return [hcg[0], f * 100, v * 100];
  };

  convert.hcg.hsl = function (hcg) {
  	var c = hcg[1] / 100;
  	var g = hcg[2] / 100;

  	var l = g * (1.0 - c) + 0.5 * c;
  	var s = 0;

  	if (l > 0.0 && l < 0.5) {
  		s = c / (2 * l);
  	} else
  	if (l >= 0.5 && l < 1.0) {
  		s = c / (2 * (1 - l));
  	}

  	return [hcg[0], s * 100, l * 100];
  };

  convert.hcg.hwb = function (hcg) {
  	var c = hcg[1] / 100;
  	var g = hcg[2] / 100;
  	var v = c + g * (1.0 - c);
  	return [hcg[0], (v - c) * 100, (1 - v) * 100];
  };

  convert.hwb.hcg = function (hwb) {
  	var w = hwb[1] / 100;
  	var b = hwb[2] / 100;
  	var v = 1 - b;
  	var c = v - w;
  	var g = 0;

  	if (c < 1) {
  		g = (v - c) / (1 - c);
  	}

  	return [hwb[0], c * 100, g * 100];
  };

  convert.apple.rgb = function (apple) {
  	return [(apple[0] / 65535) * 255, (apple[1] / 65535) * 255, (apple[2] / 65535) * 255];
  };

  convert.rgb.apple = function (rgb) {
  	return [(rgb[0] / 255) * 65535, (rgb[1] / 255) * 65535, (rgb[2] / 255) * 65535];
  };

  convert.gray.rgb = function (args) {
  	return [args[0] / 100 * 255, args[0] / 100 * 255, args[0] / 100 * 255];
  };

  convert.gray.hsl = convert.gray.hsv = function (args) {
  	return [0, 0, args[0]];
  };

  convert.gray.hwb = function (gray) {
  	return [0, 100, gray[0]];
  };

  convert.gray.cmyk = function (gray) {
  	return [0, 0, 0, gray[0]];
  };

  convert.gray.lab = function (gray) {
  	return [gray[0], 0, 0];
  };

  convert.gray.hex = function (gray) {
  	var val = Math.round(gray[0] / 100 * 255) & 0xFF;
  	var integer = (val << 16) + (val << 8) + val;

  	var string = integer.toString(16).toUpperCase();
  	return '000000'.substring(string.length) + string;
  };

  convert.rgb.gray = function (rgb) {
  	var val = (rgb[0] + rgb[1] + rgb[2]) / 3;
  	return [val / 255 * 100];
  };
  });

  /*
  	this function routes a model to all other models.

  	all functions that are routed have a property `.conversion` attached
  	to the returned synthetic function. This property is an array
  	of strings, each with the steps in between the 'from' and 'to'
  	color models (inclusive).

  	conversions that are not possible simply are not included.
  */

  function buildGraph() {
  	var graph = {};
  	// https://jsperf.com/object-keys-vs-for-in-with-closure/3
  	var models = Object.keys(conversions);

  	for (var len = models.length, i = 0; i < len; i++) {
  		graph[models[i]] = {
  			// http://jsperf.com/1-vs-infinity
  			// micro-opt, but this is simple.
  			distance: -1,
  			parent: null
  		};
  	}

  	return graph;
  }

  // https://en.wikipedia.org/wiki/Breadth-first_search
  function deriveBFS(fromModel) {
  	var graph = buildGraph();
  	var queue = [fromModel]; // unshift -> queue -> pop

  	graph[fromModel].distance = 0;

  	while (queue.length) {
  		var current = queue.pop();
  		var adjacents = Object.keys(conversions[current]);

  		for (var len = adjacents.length, i = 0; i < len; i++) {
  			var adjacent = adjacents[i];
  			var node = graph[adjacent];

  			if (node.distance === -1) {
  				node.distance = graph[current].distance + 1;
  				node.parent = current;
  				queue.unshift(adjacent);
  			}
  		}
  	}

  	return graph;
  }

  function link(from, to) {
  	return function (args) {
  		return to(from(args));
  	};
  }

  function wrapConversion(toModel, graph) {
  	var path = [graph[toModel].parent, toModel];
  	var fn = conversions[graph[toModel].parent][toModel];

  	var cur = graph[toModel].parent;
  	while (graph[cur].parent) {
  		path.unshift(graph[cur].parent);
  		fn = link(conversions[graph[cur].parent][cur], fn);
  		cur = graph[cur].parent;
  	}

  	fn.conversion = path;
  	return fn;
  }

  var route = function (fromModel) {
  	var graph = deriveBFS(fromModel);
  	var conversion = {};

  	var models = Object.keys(graph);
  	for (var len = models.length, i = 0; i < len; i++) {
  		var toModel = models[i];
  		var node = graph[toModel];

  		if (node.parent === null) {
  			// no possible conversion, or this node is the source model.
  			continue;
  		}

  		conversion[toModel] = wrapConversion(toModel, graph);
  	}

  	return conversion;
  };

  var convert = {};

  var models = Object.keys(conversions);

  function wrapRaw(fn) {
  	var wrappedFn = function (args) {
  		if (args === undefined || args === null) {
  			return args;
  		}

  		if (arguments.length > 1) {
  			args = Array.prototype.slice.call(arguments);
  		}

  		return fn(args);
  	};

  	// preserve .conversion property if there is one
  	if ('conversion' in fn) {
  		wrappedFn.conversion = fn.conversion;
  	}

  	return wrappedFn;
  }

  function wrapRounded(fn) {
  	var wrappedFn = function (args) {
  		if (args === undefined || args === null) {
  			return args;
  		}

  		if (arguments.length > 1) {
  			args = Array.prototype.slice.call(arguments);
  		}

  		var result = fn(args);

  		// we're assuming the result is an array here.
  		// see notice in conversions.js; don't use box types
  		// in conversion functions.
  		if (typeof result === 'object') {
  			for (var len = result.length, i = 0; i < len; i++) {
  				result[i] = Math.round(result[i]);
  			}
  		}

  		return result;
  	};

  	// preserve .conversion property if there is one
  	if ('conversion' in fn) {
  		wrappedFn.conversion = fn.conversion;
  	}

  	return wrappedFn;
  }

  models.forEach(function (fromModel) {
  	convert[fromModel] = {};

  	Object.defineProperty(convert[fromModel], 'channels', {value: conversions[fromModel].channels});
  	Object.defineProperty(convert[fromModel], 'labels', {value: conversions[fromModel].labels});

  	var routes = route(fromModel);
  	var routeModels = Object.keys(routes);

  	routeModels.forEach(function (toModel) {
  		var fn = routes[toModel];

  		convert[fromModel][toModel] = wrapRounded(fn);
  		convert[fromModel][toModel].raw = wrapRaw(fn);
  	});
  });

  var colorConvert = convert;

  var ansiStyles = createCommonjsModule(function (module) {


  const wrapAnsi16 = (fn, offset) => function () {
  	const code = fn.apply(colorConvert, arguments);
  	return `\u001B[${code + offset}m`;
  };

  const wrapAnsi256 = (fn, offset) => function () {
  	const code = fn.apply(colorConvert, arguments);
  	return `\u001B[${38 + offset};5;${code}m`;
  };

  const wrapAnsi16m = (fn, offset) => function () {
  	const rgb = fn.apply(colorConvert, arguments);
  	return `\u001B[${38 + offset};2;${rgb[0]};${rgb[1]};${rgb[2]}m`;
  };

  function assembleStyles() {
  	const codes = new Map();
  	const styles = {
  		modifier: {
  			reset: [0, 0],
  			// 21 isn't widely supported and 22 does the same thing
  			bold: [1, 22],
  			dim: [2, 22],
  			italic: [3, 23],
  			underline: [4, 24],
  			inverse: [7, 27],
  			hidden: [8, 28],
  			strikethrough: [9, 29]
  		},
  		color: {
  			black: [30, 39],
  			red: [31, 39],
  			green: [32, 39],
  			yellow: [33, 39],
  			blue: [34, 39],
  			magenta: [35, 39],
  			cyan: [36, 39],
  			white: [37, 39],
  			gray: [90, 39],

  			// Bright color
  			redBright: [91, 39],
  			greenBright: [92, 39],
  			yellowBright: [93, 39],
  			blueBright: [94, 39],
  			magentaBright: [95, 39],
  			cyanBright: [96, 39],
  			whiteBright: [97, 39]
  		},
  		bgColor: {
  			bgBlack: [40, 49],
  			bgRed: [41, 49],
  			bgGreen: [42, 49],
  			bgYellow: [43, 49],
  			bgBlue: [44, 49],
  			bgMagenta: [45, 49],
  			bgCyan: [46, 49],
  			bgWhite: [47, 49],

  			// Bright color
  			bgBlackBright: [100, 49],
  			bgRedBright: [101, 49],
  			bgGreenBright: [102, 49],
  			bgYellowBright: [103, 49],
  			bgBlueBright: [104, 49],
  			bgMagentaBright: [105, 49],
  			bgCyanBright: [106, 49],
  			bgWhiteBright: [107, 49]
  		}
  	};

  	// Fix humans
  	styles.color.grey = styles.color.gray;

  	for (const groupName of Object.keys(styles)) {
  		const group = styles[groupName];

  		for (const styleName of Object.keys(group)) {
  			const style = group[styleName];

  			styles[styleName] = {
  				open: `\u001B[${style[0]}m`,
  				close: `\u001B[${style[1]}m`
  			};

  			group[styleName] = styles[styleName];

  			codes.set(style[0], style[1]);
  		}

  		Object.defineProperty(styles, groupName, {
  			value: group,
  			enumerable: false
  		});

  		Object.defineProperty(styles, 'codes', {
  			value: codes,
  			enumerable: false
  		});
  	}

  	const ansi2ansi = n => n;
  	const rgb2rgb = (r, g, b) => [r, g, b];

  	styles.color.close = '\u001B[39m';
  	styles.bgColor.close = '\u001B[49m';

  	styles.color.ansi = {
  		ansi: wrapAnsi16(ansi2ansi, 0)
  	};
  	styles.color.ansi256 = {
  		ansi256: wrapAnsi256(ansi2ansi, 0)
  	};
  	styles.color.ansi16m = {
  		rgb: wrapAnsi16m(rgb2rgb, 0)
  	};

  	styles.bgColor.ansi = {
  		ansi: wrapAnsi16(ansi2ansi, 10)
  	};
  	styles.bgColor.ansi256 = {
  		ansi256: wrapAnsi256(ansi2ansi, 10)
  	};
  	styles.bgColor.ansi16m = {
  		rgb: wrapAnsi16m(rgb2rgb, 10)
  	};

  	for (let key of Object.keys(colorConvert)) {
  		if (typeof colorConvert[key] !== 'object') {
  			continue;
  		}

  		const suite = colorConvert[key];

  		if (key === 'ansi16') {
  			key = 'ansi';
  		}

  		if ('ansi16' in suite) {
  			styles.color.ansi[key] = wrapAnsi16(suite.ansi16, 0);
  			styles.bgColor.ansi[key] = wrapAnsi16(suite.ansi16, 10);
  		}

  		if ('ansi256' in suite) {
  			styles.color.ansi256[key] = wrapAnsi256(suite.ansi256, 0);
  			styles.bgColor.ansi256[key] = wrapAnsi256(suite.ansi256, 10);
  		}

  		if ('rgb' in suite) {
  			styles.color.ansi16m[key] = wrapAnsi16m(suite.rgb, 0);
  			styles.bgColor.ansi16m[key] = wrapAnsi16m(suite.rgb, 10);
  		}
  	}

  	return styles;
  }

  // Make the export immutable
  Object.defineProperty(module, 'exports', {
  	enumerable: true,
  	get: assembleStyles
  });
  });

  const env$1 = process.env;

  let forceColor$1;
  if (hasFlag('no-color') ||
  	hasFlag('no-colors') ||
  	hasFlag('color=false')) {
  	forceColor$1 = false;
  } else if (hasFlag('color') ||
  	hasFlag('colors') ||
  	hasFlag('color=true') ||
  	hasFlag('color=always')) {
  	forceColor$1 = true;
  }
  if ('FORCE_COLOR' in env$1) {
  	forceColor$1 = env$1.FORCE_COLOR.length === 0 || parseInt(env$1.FORCE_COLOR, 10) !== 0;
  }

  function translateLevel$1(level) {
  	if (level === 0) {
  		return false;
  	}

  	return {
  		level,
  		hasBasic: true,
  		has256: level >= 2,
  		has16m: level >= 3
  	};
  }

  function supportsColor$1(stream) {
  	if (forceColor$1 === false) {
  		return 0;
  	}

  	if (hasFlag('color=16m') ||
  		hasFlag('color=full') ||
  		hasFlag('color=truecolor')) {
  		return 3;
  	}

  	if (hasFlag('color=256')) {
  		return 2;
  	}

  	if (stream && !stream.isTTY && forceColor$1 !== true) {
  		return 0;
  	}

  	const min = forceColor$1 ? 1 : 0;

  	if (process.platform === 'win32') {
  		// Node.js 7.5.0 is the first version of Node.js to include a patch to
  		// libuv that enables 256 color output on Windows. Anything earlier and it
  		// won't work. However, here we target Node.js 8 at minimum as it is an LTS
  		// release, and Node.js 7 is not. Windows 10 build 10586 is the first Windows
  		// release that supports 256 colors. Windows 10 build 14931 is the first release
  		// that supports 16m/TrueColor.
  		const osRelease = os__default['default'].release().split('.');
  		if (
  			Number(process.versions.node.split('.')[0]) >= 8 &&
  			Number(osRelease[0]) >= 10 &&
  			Number(osRelease[2]) >= 10586
  		) {
  			return Number(osRelease[2]) >= 14931 ? 3 : 2;
  		}

  		return 1;
  	}

  	if ('CI' in env$1) {
  		if (['TRAVIS', 'CIRCLECI', 'APPVEYOR', 'GITLAB_CI'].some(sign => sign in env$1) || env$1.CI_NAME === 'codeship') {
  			return 1;
  		}

  		return min;
  	}

  	if ('TEAMCITY_VERSION' in env$1) {
  		return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(env$1.TEAMCITY_VERSION) ? 1 : 0;
  	}

  	if (env$1.COLORTERM === 'truecolor') {
  		return 3;
  	}

  	if ('TERM_PROGRAM' in env$1) {
  		const version = parseInt((env$1.TERM_PROGRAM_VERSION || '').split('.')[0], 10);

  		switch (env$1.TERM_PROGRAM) {
  			case 'iTerm.app':
  				return version >= 3 ? 3 : 2;
  			case 'Apple_Terminal':
  				return 2;
  			// No default
  		}
  	}

  	if (/-256(color)?$/i.test(env$1.TERM)) {
  		return 2;
  	}

  	if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(env$1.TERM)) {
  		return 1;
  	}

  	if ('COLORTERM' in env$1) {
  		return 1;
  	}

  	if (env$1.TERM === 'dumb') {
  		return min;
  	}

  	return min;
  }

  function getSupportLevel$1(stream) {
  	const level = supportsColor$1(stream);
  	return translateLevel$1(level);
  }

  var supportsColor_1$1 = {
  	supportsColor: getSupportLevel$1,
  	stdout: getSupportLevel$1(process.stdout),
  	stderr: getSupportLevel$1(process.stderr)
  };

  const TEMPLATE_REGEX = /(?:\\(u[a-f\d]{4}|x[a-f\d]{2}|.))|(?:\{(~)?(\w+(?:\([^)]*\))?(?:\.\w+(?:\([^)]*\))?)*)(?:[ \t]|(?=\r?\n)))|(\})|((?:.|[\r\n\f])+?)/gi;
  const STYLE_REGEX = /(?:^|\.)(\w+)(?:\(([^)]*)\))?/g;
  const STRING_REGEX = /^(['"])((?:\\.|(?!\1)[^\\])*)\1$/;
  const ESCAPE_REGEX = /\\(u[a-f\d]{4}|x[a-f\d]{2}|.)|([^\\])/gi;

  const ESCAPES = new Map([
  	['n', '\n'],
  	['r', '\r'],
  	['t', '\t'],
  	['b', '\b'],
  	['f', '\f'],
  	['v', '\v'],
  	['0', '\0'],
  	['\\', '\\'],
  	['e', '\u001B'],
  	['a', '\u0007']
  ]);

  function unescape$1(c) {
  	if ((c[0] === 'u' && c.length === 5) || (c[0] === 'x' && c.length === 3)) {
  		return String.fromCharCode(parseInt(c.slice(1), 16));
  	}

  	return ESCAPES.get(c) || c;
  }

  function parseArguments(name, args) {
  	const results = [];
  	const chunks = args.trim().split(/\s*,\s*/g);
  	let matches;

  	for (const chunk of chunks) {
  		if (!isNaN(chunk)) {
  			results.push(Number(chunk));
  		} else if ((matches = chunk.match(STRING_REGEX))) {
  			results.push(matches[2].replace(ESCAPE_REGEX, (m, escape, chr) => escape ? unescape$1(escape) : chr));
  		} else {
  			throw new Error(`Invalid Chalk template style argument: ${chunk} (in style '${name}')`);
  		}
  	}

  	return results;
  }

  function parseStyle(style) {
  	STYLE_REGEX.lastIndex = 0;

  	const results = [];
  	let matches;

  	while ((matches = STYLE_REGEX.exec(style)) !== null) {
  		const name = matches[1];

  		if (matches[2]) {
  			const args = parseArguments(name, matches[2]);
  			results.push([name].concat(args));
  		} else {
  			results.push([name]);
  		}
  	}

  	return results;
  }

  function buildStyle(chalk, styles) {
  	const enabled = {};

  	for (const layer of styles) {
  		for (const style of layer.styles) {
  			enabled[style[0]] = layer.inverse ? null : style.slice(1);
  		}
  	}

  	let current = chalk;
  	for (const styleName of Object.keys(enabled)) {
  		if (Array.isArray(enabled[styleName])) {
  			if (!(styleName in current)) {
  				throw new Error(`Unknown Chalk style: ${styleName}`);
  			}

  			if (enabled[styleName].length > 0) {
  				current = current[styleName].apply(current, enabled[styleName]);
  			} else {
  				current = current[styleName];
  			}
  		}
  	}

  	return current;
  }

  var templates = (chalk, tmp) => {
  	const styles = [];
  	const chunks = [];
  	let chunk = [];

  	// eslint-disable-next-line max-params
  	tmp.replace(TEMPLATE_REGEX, (m, escapeChar, inverse, style, close, chr) => {
  		if (escapeChar) {
  			chunk.push(unescape$1(escapeChar));
  		} else if (style) {
  			const str = chunk.join('');
  			chunk = [];
  			chunks.push(styles.length === 0 ? str : buildStyle(chalk, styles)(str));
  			styles.push({inverse, styles: parseStyle(style)});
  		} else if (close) {
  			if (styles.length === 0) {
  				throw new Error('Found extraneous } in Chalk template literal');
  			}

  			chunks.push(buildStyle(chalk, styles)(chunk.join('')));
  			chunk = [];
  			styles.pop();
  		} else {
  			chunk.push(chr);
  		}
  	});

  	chunks.push(chunk.join(''));

  	if (styles.length > 0) {
  		const errMsg = `Chalk template literal is missing ${styles.length} closing bracket${styles.length === 1 ? '' : 's'} (\`}\`)`;
  		throw new Error(errMsg);
  	}

  	return chunks.join('');
  };

  var chalk = createCommonjsModule(function (module) {


  const stdoutColor = supportsColor_1$1.stdout;



  const isSimpleWindowsTerm = process.platform === 'win32' && !(process.env.TERM || '').toLowerCase().startsWith('xterm');

  // `supportsColor.level` → `ansiStyles.color[name]` mapping
  const levelMapping = ['ansi', 'ansi', 'ansi256', 'ansi16m'];

  // `color-convert` models to exclude from the Chalk API due to conflicts and such
  const skipModels = new Set(['gray']);

  const styles = Object.create(null);

  function applyOptions(obj, options) {
  	options = options || {};

  	// Detect level if not set manually
  	const scLevel = stdoutColor ? stdoutColor.level : 0;
  	obj.level = options.level === undefined ? scLevel : options.level;
  	obj.enabled = 'enabled' in options ? options.enabled : obj.level > 0;
  }

  function Chalk(options) {
  	// We check for this.template here since calling `chalk.constructor()`
  	// by itself will have a `this` of a previously constructed chalk object
  	if (!this || !(this instanceof Chalk) || this.template) {
  		const chalk = {};
  		applyOptions(chalk, options);

  		chalk.template = function () {
  			const args = [].slice.call(arguments);
  			return chalkTag.apply(null, [chalk.template].concat(args));
  		};

  		Object.setPrototypeOf(chalk, Chalk.prototype);
  		Object.setPrototypeOf(chalk.template, chalk);

  		chalk.template.constructor = Chalk;

  		return chalk.template;
  	}

  	applyOptions(this, options);
  }

  // Use bright blue on Windows as the normal blue color is illegible
  if (isSimpleWindowsTerm) {
  	ansiStyles.blue.open = '\u001B[94m';
  }

  for (const key of Object.keys(ansiStyles)) {
  	ansiStyles[key].closeRe = new RegExp(escapeStringRegexp(ansiStyles[key].close), 'g');

  	styles[key] = {
  		get() {
  			const codes = ansiStyles[key];
  			return build.call(this, this._styles ? this._styles.concat(codes) : [codes], this._empty, key);
  		}
  	};
  }

  styles.visible = {
  	get() {
  		return build.call(this, this._styles || [], true, 'visible');
  	}
  };

  ansiStyles.color.closeRe = new RegExp(escapeStringRegexp(ansiStyles.color.close), 'g');
  for (const model of Object.keys(ansiStyles.color.ansi)) {
  	if (skipModels.has(model)) {
  		continue;
  	}

  	styles[model] = {
  		get() {
  			const level = this.level;
  			return function () {
  				const open = ansiStyles.color[levelMapping[level]][model].apply(null, arguments);
  				const codes = {
  					open,
  					close: ansiStyles.color.close,
  					closeRe: ansiStyles.color.closeRe
  				};
  				return build.call(this, this._styles ? this._styles.concat(codes) : [codes], this._empty, model);
  			};
  		}
  	};
  }

  ansiStyles.bgColor.closeRe = new RegExp(escapeStringRegexp(ansiStyles.bgColor.close), 'g');
  for (const model of Object.keys(ansiStyles.bgColor.ansi)) {
  	if (skipModels.has(model)) {
  		continue;
  	}

  	const bgModel = 'bg' + model[0].toUpperCase() + model.slice(1);
  	styles[bgModel] = {
  		get() {
  			const level = this.level;
  			return function () {
  				const open = ansiStyles.bgColor[levelMapping[level]][model].apply(null, arguments);
  				const codes = {
  					open,
  					close: ansiStyles.bgColor.close,
  					closeRe: ansiStyles.bgColor.closeRe
  				};
  				return build.call(this, this._styles ? this._styles.concat(codes) : [codes], this._empty, model);
  			};
  		}
  	};
  }

  const proto = Object.defineProperties(() => {}, styles);

  function build(_styles, _empty, key) {
  	const builder = function () {
  		return applyStyle.apply(builder, arguments);
  	};

  	builder._styles = _styles;
  	builder._empty = _empty;

  	const self = this;

  	Object.defineProperty(builder, 'level', {
  		enumerable: true,
  		get() {
  			return self.level;
  		},
  		set(level) {
  			self.level = level;
  		}
  	});

  	Object.defineProperty(builder, 'enabled', {
  		enumerable: true,
  		get() {
  			return self.enabled;
  		},
  		set(enabled) {
  			self.enabled = enabled;
  		}
  	});

  	// See below for fix regarding invisible grey/dim combination on Windows
  	builder.hasGrey = this.hasGrey || key === 'gray' || key === 'grey';

  	// `__proto__` is used because we must return a function, but there is
  	// no way to create a function with a different prototype
  	builder.__proto__ = proto; // eslint-disable-line no-proto

  	return builder;
  }

  function applyStyle() {
  	// Support varags, but simply cast to string in case there's only one arg
  	const args = arguments;
  	const argsLen = args.length;
  	let str = String(arguments[0]);

  	if (argsLen === 0) {
  		return '';
  	}

  	if (argsLen > 1) {
  		// Don't slice `arguments`, it prevents V8 optimizations
  		for (let a = 1; a < argsLen; a++) {
  			str += ' ' + args[a];
  		}
  	}

  	if (!this.enabled || this.level <= 0 || !str) {
  		return this._empty ? '' : str;
  	}

  	// Turns out that on Windows dimmed gray text becomes invisible in cmd.exe,
  	// see https://github.com/chalk/chalk/issues/58
  	// If we're on Windows and we're dealing with a gray color, temporarily make 'dim' a noop.
  	const originalDim = ansiStyles.dim.open;
  	if (isSimpleWindowsTerm && this.hasGrey) {
  		ansiStyles.dim.open = '';
  	}

  	for (const code of this._styles.slice().reverse()) {
  		// Replace any instances already present with a re-opening code
  		// otherwise only the part of the string until said closing code
  		// will be colored, and the rest will simply be 'plain'.
  		str = code.open + str.replace(code.closeRe, code.open) + code.close;

  		// Close the styling before a linebreak and reopen
  		// after next line to fix a bleed issue on macOS
  		// https://github.com/chalk/chalk/pull/92
  		str = str.replace(/\r?\n/g, `${code.close}$&${code.open}`);
  	}

  	// Reset the original `dim` if we changed it to work around the Windows dimmed gray issue
  	ansiStyles.dim.open = originalDim;

  	return str;
  }

  function chalkTag(chalk, strings) {
  	if (!Array.isArray(strings)) {
  		// If chalk() was called by itself or with a string,
  		// return the string itself as a string.
  		return [].slice.call(arguments, 1).join(' ');
  	}

  	const args = [].slice.call(arguments, 2);
  	const parts = [strings.raw[0]];

  	for (let i = 1; i < strings.length; i++) {
  		parts.push(String(args[i - 1]).replace(/[{}\\]/g, '\\$&'));
  		parts.push(String(strings.raw[i]));
  	}

  	return templates(chalk, parts.join(''));
  }

  Object.defineProperties(Chalk.prototype, styles);

  module.exports = Chalk(); // eslint-disable-line new-cap
  module.exports.supportsColor = stdoutColor;
  module.exports.default = module.exports; // For TypeScript
  });

  var tokenize = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = tokenizer;
  var SINGLE_QUOTE = '\''.charCodeAt(0);
  var DOUBLE_QUOTE = '"'.charCodeAt(0);
  var BACKSLASH = '\\'.charCodeAt(0);
  var SLASH = '/'.charCodeAt(0);
  var NEWLINE = '\n'.charCodeAt(0);
  var SPACE = ' '.charCodeAt(0);
  var FEED = '\f'.charCodeAt(0);
  var TAB = '\t'.charCodeAt(0);
  var CR = '\r'.charCodeAt(0);
  var OPEN_SQUARE = '['.charCodeAt(0);
  var CLOSE_SQUARE = ']'.charCodeAt(0);
  var OPEN_PARENTHESES = '('.charCodeAt(0);
  var CLOSE_PARENTHESES = ')'.charCodeAt(0);
  var OPEN_CURLY = '{'.charCodeAt(0);
  var CLOSE_CURLY = '}'.charCodeAt(0);
  var SEMICOLON = ';'.charCodeAt(0);
  var ASTERISK = '*'.charCodeAt(0);
  var COLON = ':'.charCodeAt(0);
  var AT = '@'.charCodeAt(0);
  var RE_AT_END = /[ \n\t\r\f{}()'"\\;/[\]#]/g;
  var RE_WORD_END = /[ \n\t\r\f(){}:;@!'"\\\][#]|\/(?=\*)/g;
  var RE_BAD_BRACKET = /.[\\/("'\n]/;
  var RE_HEX_ESCAPE = /[a-f0-9]/i;

  function tokenizer(input, options) {
    if (options === void 0) {
      options = {};
    }

    var css = input.css.valueOf();
    var ignore = options.ignoreErrors;
    var code, next, quote, lines, last, content, escape;
    var nextLine, nextOffset, escaped, escapePos, prev, n, currentToken;
    var length = css.length;
    var offset = -1;
    var line = 1;
    var pos = 0;
    var buffer = [];
    var returned = [];

    function position() {
      return pos;
    }

    function unclosed(what) {
      throw input.error('Unclosed ' + what, line, pos - offset);
    }

    function endOfFile() {
      return returned.length === 0 && pos >= length;
    }

    function nextToken(opts) {
      if (returned.length) return returned.pop();
      if (pos >= length) return;
      var ignoreUnclosed = opts ? opts.ignoreUnclosed : false;
      code = css.charCodeAt(pos);

      if (code === NEWLINE || code === FEED || code === CR && css.charCodeAt(pos + 1) !== NEWLINE) {
        offset = pos;
        line += 1;
      }

      switch (code) {
        case NEWLINE:
        case SPACE:
        case TAB:
        case CR:
        case FEED:
          next = pos;

          do {
            next += 1;
            code = css.charCodeAt(next);

            if (code === NEWLINE) {
              offset = next;
              line += 1;
            }
          } while (code === SPACE || code === NEWLINE || code === TAB || code === CR || code === FEED);

          currentToken = ['space', css.slice(pos, next)];
          pos = next - 1;
          break;

        case OPEN_SQUARE:
        case CLOSE_SQUARE:
        case OPEN_CURLY:
        case CLOSE_CURLY:
        case COLON:
        case SEMICOLON:
        case CLOSE_PARENTHESES:
          var controlChar = String.fromCharCode(code);
          currentToken = [controlChar, controlChar, line, pos - offset];
          break;

        case OPEN_PARENTHESES:
          prev = buffer.length ? buffer.pop()[1] : '';
          n = css.charCodeAt(pos + 1);

          if (prev === 'url' && n !== SINGLE_QUOTE && n !== DOUBLE_QUOTE && n !== SPACE && n !== NEWLINE && n !== TAB && n !== FEED && n !== CR) {
            next = pos;

            do {
              escaped = false;
              next = css.indexOf(')', next + 1);

              if (next === -1) {
                if (ignore || ignoreUnclosed) {
                  next = pos;
                  break;
                } else {
                  unclosed('bracket');
                }
              }

              escapePos = next;

              while (css.charCodeAt(escapePos - 1) === BACKSLASH) {
                escapePos -= 1;
                escaped = !escaped;
              }
            } while (escaped);

            currentToken = ['brackets', css.slice(pos, next + 1), line, pos - offset, line, next - offset];
            pos = next;
          } else {
            next = css.indexOf(')', pos + 1);
            content = css.slice(pos, next + 1);

            if (next === -1 || RE_BAD_BRACKET.test(content)) {
              currentToken = ['(', '(', line, pos - offset];
            } else {
              currentToken = ['brackets', content, line, pos - offset, line, next - offset];
              pos = next;
            }
          }

          break;

        case SINGLE_QUOTE:
        case DOUBLE_QUOTE:
          quote = code === SINGLE_QUOTE ? '\'' : '"';
          next = pos;

          do {
            escaped = false;
            next = css.indexOf(quote, next + 1);

            if (next === -1) {
              if (ignore || ignoreUnclosed) {
                next = pos + 1;
                break;
              } else {
                unclosed('string');
              }
            }

            escapePos = next;

            while (css.charCodeAt(escapePos - 1) === BACKSLASH) {
              escapePos -= 1;
              escaped = !escaped;
            }
          } while (escaped);

          content = css.slice(pos, next + 1);
          lines = content.split('\n');
          last = lines.length - 1;

          if (last > 0) {
            nextLine = line + last;
            nextOffset = next - lines[last].length;
          } else {
            nextLine = line;
            nextOffset = offset;
          }

          currentToken = ['string', css.slice(pos, next + 1), line, pos - offset, nextLine, next - nextOffset];
          offset = nextOffset;
          line = nextLine;
          pos = next;
          break;

        case AT:
          RE_AT_END.lastIndex = pos + 1;
          RE_AT_END.test(css);

          if (RE_AT_END.lastIndex === 0) {
            next = css.length - 1;
          } else {
            next = RE_AT_END.lastIndex - 2;
          }

          currentToken = ['at-word', css.slice(pos, next + 1), line, pos - offset, line, next - offset];
          pos = next;
          break;

        case BACKSLASH:
          next = pos;
          escape = true;

          while (css.charCodeAt(next + 1) === BACKSLASH) {
            next += 1;
            escape = !escape;
          }

          code = css.charCodeAt(next + 1);

          if (escape && code !== SLASH && code !== SPACE && code !== NEWLINE && code !== TAB && code !== CR && code !== FEED) {
            next += 1;

            if (RE_HEX_ESCAPE.test(css.charAt(next))) {
              while (RE_HEX_ESCAPE.test(css.charAt(next + 1))) {
                next += 1;
              }

              if (css.charCodeAt(next + 1) === SPACE) {
                next += 1;
              }
            }
          }

          currentToken = ['word', css.slice(pos, next + 1), line, pos - offset, line, next - offset];
          pos = next;
          break;

        default:
          if (code === SLASH && css.charCodeAt(pos + 1) === ASTERISK) {
            next = css.indexOf('*/', pos + 2) + 1;

            if (next === 0) {
              if (ignore || ignoreUnclosed) {
                next = css.length;
              } else {
                unclosed('comment');
              }
            }

            content = css.slice(pos, next + 1);
            lines = content.split('\n');
            last = lines.length - 1;

            if (last > 0) {
              nextLine = line + last;
              nextOffset = next - lines[last].length;
            } else {
              nextLine = line;
              nextOffset = offset;
            }

            currentToken = ['comment', content, line, pos - offset, nextLine, next - nextOffset];
            offset = nextOffset;
            line = nextLine;
            pos = next;
          } else {
            RE_WORD_END.lastIndex = pos + 1;
            RE_WORD_END.test(css);

            if (RE_WORD_END.lastIndex === 0) {
              next = css.length - 1;
            } else {
              next = RE_WORD_END.lastIndex - 2;
            }

            currentToken = ['word', css.slice(pos, next + 1), line, pos - offset, line, next - offset];
            buffer.push(currentToken);
            pos = next;
          }

          break;
      }

      pos++;
      return currentToken;
    }

    function back(token) {
      returned.push(token);
    }

    return {
      back: back,
      nextToken: nextToken,
      endOfFile: endOfFile,
      position: position
    };
  }

  module.exports = exports.default;

  });

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */

  var intToCharMap = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split('');

  /**
   * Encode an integer in the range of 0 to 63 to a single base 64 digit.
   */
  var encode = function (number) {
    if (0 <= number && number < intToCharMap.length) {
      return intToCharMap[number];
    }
    throw new TypeError("Must be between 0 and 63: " + number);
  };

  /**
   * Decode a single base 64 character code digit to an integer. Returns -1 on
   * failure.
   */
  var decode = function (charCode) {
    var bigA = 65;     // 'A'
    var bigZ = 90;     // 'Z'

    var littleA = 97;  // 'a'
    var littleZ = 122; // 'z'

    var zero = 48;     // '0'
    var nine = 57;     // '9'

    var plus = 43;     // '+'
    var slash = 47;    // '/'

    var littleOffset = 26;
    var numberOffset = 52;

    // 0 - 25: ABCDEFGHIJKLMNOPQRSTUVWXYZ
    if (bigA <= charCode && charCode <= bigZ) {
      return (charCode - bigA);
    }

    // 26 - 51: abcdefghijklmnopqrstuvwxyz
    if (littleA <= charCode && charCode <= littleZ) {
      return (charCode - littleA + littleOffset);
    }

    // 52 - 61: 0123456789
    if (zero <= charCode && charCode <= nine) {
      return (charCode - zero + numberOffset);
    }

    // 62: +
    if (charCode == plus) {
      return 62;
    }

    // 63: /
    if (charCode == slash) {
      return 63;
    }

    // Invalid base64 digit.
    return -1;
  };

  var base64 = {
  	encode: encode,
  	decode: decode
  };

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   *
   * Based on the Base 64 VLQ implementation in Closure Compiler:
   * https://code.google.com/p/closure-compiler/source/browse/trunk/src/com/google/debugging/sourcemap/Base64VLQ.java
   *
   * Copyright 2011 The Closure Compiler Authors. All rights reserved.
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions are
   * met:
   *
   *  * Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   *  * Redistributions in binary form must reproduce the above
   *    copyright notice, this list of conditions and the following
   *    disclaimer in the documentation and/or other materials provided
   *    with the distribution.
   *  * Neither the name of Google Inc. nor the names of its
   *    contributors may be used to endorse or promote products derived
   *    from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */



  // A single base 64 digit can contain 6 bits of data. For the base 64 variable
  // length quantities we use in the source map spec, the first bit is the sign,
  // the next four bits are the actual value, and the 6th bit is the
  // continuation bit. The continuation bit tells us whether there are more
  // digits in this value following this digit.
  //
  //   Continuation
  //   |    Sign
  //   |    |
  //   V    V
  //   101011

  var VLQ_BASE_SHIFT = 5;

  // binary: 100000
  var VLQ_BASE = 1 << VLQ_BASE_SHIFT;

  // binary: 011111
  var VLQ_BASE_MASK = VLQ_BASE - 1;

  // binary: 100000
  var VLQ_CONTINUATION_BIT = VLQ_BASE;

  /**
   * Converts from a two-complement value to a value where the sign bit is
   * placed in the least significant bit.  For example, as decimals:
   *   1 becomes 2 (10 binary), -1 becomes 3 (11 binary)
   *   2 becomes 4 (100 binary), -2 becomes 5 (101 binary)
   */
  function toVLQSigned(aValue) {
    return aValue < 0
      ? ((-aValue) << 1) + 1
      : (aValue << 1) + 0;
  }

  /**
   * Converts to a two-complement value from a value where the sign bit is
   * placed in the least significant bit.  For example, as decimals:
   *   2 (10 binary) becomes 1, 3 (11 binary) becomes -1
   *   4 (100 binary) becomes 2, 5 (101 binary) becomes -2
   */
  function fromVLQSigned(aValue) {
    var isNegative = (aValue & 1) === 1;
    var shifted = aValue >> 1;
    return isNegative
      ? -shifted
      : shifted;
  }

  /**
   * Returns the base 64 VLQ encoded value.
   */
  var encode$1 = function base64VLQ_encode(aValue) {
    var encoded = "";
    var digit;

    var vlq = toVLQSigned(aValue);

    do {
      digit = vlq & VLQ_BASE_MASK;
      vlq >>>= VLQ_BASE_SHIFT;
      if (vlq > 0) {
        // There are still more digits in this value, so we must make sure the
        // continuation bit is marked.
        digit |= VLQ_CONTINUATION_BIT;
      }
      encoded += base64.encode(digit);
    } while (vlq > 0);

    return encoded;
  };

  /**
   * Decodes the next base 64 VLQ value from the given string and returns the
   * value and the rest of the string via the out parameter.
   */
  var decode$1 = function base64VLQ_decode(aStr, aIndex, aOutParam) {
    var strLen = aStr.length;
    var result = 0;
    var shift = 0;
    var continuation, digit;

    do {
      if (aIndex >= strLen) {
        throw new Error("Expected more digits in base 64 VLQ value.");
      }

      digit = base64.decode(aStr.charCodeAt(aIndex++));
      if (digit === -1) {
        throw new Error("Invalid base64 digit: " + aStr.charAt(aIndex - 1));
      }

      continuation = !!(digit & VLQ_CONTINUATION_BIT);
      digit &= VLQ_BASE_MASK;
      result = result + (digit << shift);
      shift += VLQ_BASE_SHIFT;
    } while (continuation);

    aOutParam.value = fromVLQSigned(result);
    aOutParam.rest = aIndex;
  };

  var base64Vlq = {
  	encode: encode$1,
  	decode: decode$1
  };

  var util = createCommonjsModule(function (module, exports) {
  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */

  /**
   * This is a helper function for getting values from parameter/options
   * objects.
   *
   * @param args The object we are extracting values from
   * @param name The name of the property we are getting.
   * @param defaultValue An optional value to return if the property is missing
   * from the object. If this is not specified and the property is missing, an
   * error will be thrown.
   */
  function getArg(aArgs, aName, aDefaultValue) {
    if (aName in aArgs) {
      return aArgs[aName];
    } else if (arguments.length === 3) {
      return aDefaultValue;
    } else {
      throw new Error('"' + aName + '" is a required argument.');
    }
  }
  exports.getArg = getArg;

  var urlRegexp = /^(?:([\w+\-.]+):)?\/\/(?:(\w+:\w+)@)?([\w.-]*)(?::(\d+))?(.*)$/;
  var dataUrlRegexp = /^data:.+\,.+$/;

  function urlParse(aUrl) {
    var match = aUrl.match(urlRegexp);
    if (!match) {
      return null;
    }
    return {
      scheme: match[1],
      auth: match[2],
      host: match[3],
      port: match[4],
      path: match[5]
    };
  }
  exports.urlParse = urlParse;

  function urlGenerate(aParsedUrl) {
    var url = '';
    if (aParsedUrl.scheme) {
      url += aParsedUrl.scheme + ':';
    }
    url += '//';
    if (aParsedUrl.auth) {
      url += aParsedUrl.auth + '@';
    }
    if (aParsedUrl.host) {
      url += aParsedUrl.host;
    }
    if (aParsedUrl.port) {
      url += ":" + aParsedUrl.port;
    }
    if (aParsedUrl.path) {
      url += aParsedUrl.path;
    }
    return url;
  }
  exports.urlGenerate = urlGenerate;

  /**
   * Normalizes a path, or the path portion of a URL:
   *
   * - Replaces consecutive slashes with one slash.
   * - Removes unnecessary '.' parts.
   * - Removes unnecessary '<dir>/..' parts.
   *
   * Based on code in the Node.js 'path' core module.
   *
   * @param aPath The path or url to normalize.
   */
  function normalize(aPath) {
    var path = aPath;
    var url = urlParse(aPath);
    if (url) {
      if (!url.path) {
        return aPath;
      }
      path = url.path;
    }
    var isAbsolute = exports.isAbsolute(path);

    var parts = path.split(/\/+/);
    for (var part, up = 0, i = parts.length - 1; i >= 0; i--) {
      part = parts[i];
      if (part === '.') {
        parts.splice(i, 1);
      } else if (part === '..') {
        up++;
      } else if (up > 0) {
        if (part === '') {
          // The first part is blank if the path is absolute. Trying to go
          // above the root is a no-op. Therefore we can remove all '..' parts
          // directly after the root.
          parts.splice(i + 1, up);
          up = 0;
        } else {
          parts.splice(i, 2);
          up--;
        }
      }
    }
    path = parts.join('/');

    if (path === '') {
      path = isAbsolute ? '/' : '.';
    }

    if (url) {
      url.path = path;
      return urlGenerate(url);
    }
    return path;
  }
  exports.normalize = normalize;

  /**
   * Joins two paths/URLs.
   *
   * @param aRoot The root path or URL.
   * @param aPath The path or URL to be joined with the root.
   *
   * - If aPath is a URL or a data URI, aPath is returned, unless aPath is a
   *   scheme-relative URL: Then the scheme of aRoot, if any, is prepended
   *   first.
   * - Otherwise aPath is a path. If aRoot is a URL, then its path portion
   *   is updated with the result and aRoot is returned. Otherwise the result
   *   is returned.
   *   - If aPath is absolute, the result is aPath.
   *   - Otherwise the two paths are joined with a slash.
   * - Joining for example 'http://' and 'www.example.com' is also supported.
   */
  function join(aRoot, aPath) {
    if (aRoot === "") {
      aRoot = ".";
    }
    if (aPath === "") {
      aPath = ".";
    }
    var aPathUrl = urlParse(aPath);
    var aRootUrl = urlParse(aRoot);
    if (aRootUrl) {
      aRoot = aRootUrl.path || '/';
    }

    // `join(foo, '//www.example.org')`
    if (aPathUrl && !aPathUrl.scheme) {
      if (aRootUrl) {
        aPathUrl.scheme = aRootUrl.scheme;
      }
      return urlGenerate(aPathUrl);
    }

    if (aPathUrl || aPath.match(dataUrlRegexp)) {
      return aPath;
    }

    // `join('http://', 'www.example.com')`
    if (aRootUrl && !aRootUrl.host && !aRootUrl.path) {
      aRootUrl.host = aPath;
      return urlGenerate(aRootUrl);
    }

    var joined = aPath.charAt(0) === '/'
      ? aPath
      : normalize(aRoot.replace(/\/+$/, '') + '/' + aPath);

    if (aRootUrl) {
      aRootUrl.path = joined;
      return urlGenerate(aRootUrl);
    }
    return joined;
  }
  exports.join = join;

  exports.isAbsolute = function (aPath) {
    return aPath.charAt(0) === '/' || urlRegexp.test(aPath);
  };

  /**
   * Make a path relative to a URL or another path.
   *
   * @param aRoot The root path or URL.
   * @param aPath The path or URL to be made relative to aRoot.
   */
  function relative(aRoot, aPath) {
    if (aRoot === "") {
      aRoot = ".";
    }

    aRoot = aRoot.replace(/\/$/, '');

    // It is possible for the path to be above the root. In this case, simply
    // checking whether the root is a prefix of the path won't work. Instead, we
    // need to remove components from the root one by one, until either we find
    // a prefix that fits, or we run out of components to remove.
    var level = 0;
    while (aPath.indexOf(aRoot + '/') !== 0) {
      var index = aRoot.lastIndexOf("/");
      if (index < 0) {
        return aPath;
      }

      // If the only part of the root that is left is the scheme (i.e. http://,
      // file:///, etc.), one or more slashes (/), or simply nothing at all, we
      // have exhausted all components, so the path is not relative to the root.
      aRoot = aRoot.slice(0, index);
      if (aRoot.match(/^([^\/]+:\/)?\/*$/)) {
        return aPath;
      }

      ++level;
    }

    // Make sure we add a "../" for each component we removed from the root.
    return Array(level + 1).join("../") + aPath.substr(aRoot.length + 1);
  }
  exports.relative = relative;

  var supportsNullProto = (function () {
    var obj = Object.create(null);
    return !('__proto__' in obj);
  }());

  function identity (s) {
    return s;
  }

  /**
   * Because behavior goes wacky when you set `__proto__` on objects, we
   * have to prefix all the strings in our set with an arbitrary character.
   *
   * See https://github.com/mozilla/source-map/pull/31 and
   * https://github.com/mozilla/source-map/issues/30
   *
   * @param String aStr
   */
  function toSetString(aStr) {
    if (isProtoString(aStr)) {
      return '$' + aStr;
    }

    return aStr;
  }
  exports.toSetString = supportsNullProto ? identity : toSetString;

  function fromSetString(aStr) {
    if (isProtoString(aStr)) {
      return aStr.slice(1);
    }

    return aStr;
  }
  exports.fromSetString = supportsNullProto ? identity : fromSetString;

  function isProtoString(s) {
    if (!s) {
      return false;
    }

    var length = s.length;

    if (length < 9 /* "__proto__".length */) {
      return false;
    }

    if (s.charCodeAt(length - 1) !== 95  /* '_' */ ||
        s.charCodeAt(length - 2) !== 95  /* '_' */ ||
        s.charCodeAt(length - 3) !== 111 /* 'o' */ ||
        s.charCodeAt(length - 4) !== 116 /* 't' */ ||
        s.charCodeAt(length - 5) !== 111 /* 'o' */ ||
        s.charCodeAt(length - 6) !== 114 /* 'r' */ ||
        s.charCodeAt(length - 7) !== 112 /* 'p' */ ||
        s.charCodeAt(length - 8) !== 95  /* '_' */ ||
        s.charCodeAt(length - 9) !== 95  /* '_' */) {
      return false;
    }

    for (var i = length - 10; i >= 0; i--) {
      if (s.charCodeAt(i) !== 36 /* '$' */) {
        return false;
      }
    }

    return true;
  }

  /**
   * Comparator between two mappings where the original positions are compared.
   *
   * Optionally pass in `true` as `onlyCompareGenerated` to consider two
   * mappings with the same original source/line/column, but different generated
   * line and column the same. Useful when searching for a mapping with a
   * stubbed out mapping.
   */
  function compareByOriginalPositions(mappingA, mappingB, onlyCompareOriginal) {
    var cmp = strcmp(mappingA.source, mappingB.source);
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.originalLine - mappingB.originalLine;
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.originalColumn - mappingB.originalColumn;
    if (cmp !== 0 || onlyCompareOriginal) {
      return cmp;
    }

    cmp = mappingA.generatedColumn - mappingB.generatedColumn;
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.generatedLine - mappingB.generatedLine;
    if (cmp !== 0) {
      return cmp;
    }

    return strcmp(mappingA.name, mappingB.name);
  }
  exports.compareByOriginalPositions = compareByOriginalPositions;

  /**
   * Comparator between two mappings with deflated source and name indices where
   * the generated positions are compared.
   *
   * Optionally pass in `true` as `onlyCompareGenerated` to consider two
   * mappings with the same generated line and column, but different
   * source/name/original line and column the same. Useful when searching for a
   * mapping with a stubbed out mapping.
   */
  function compareByGeneratedPositionsDeflated(mappingA, mappingB, onlyCompareGenerated) {
    var cmp = mappingA.generatedLine - mappingB.generatedLine;
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.generatedColumn - mappingB.generatedColumn;
    if (cmp !== 0 || onlyCompareGenerated) {
      return cmp;
    }

    cmp = strcmp(mappingA.source, mappingB.source);
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.originalLine - mappingB.originalLine;
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.originalColumn - mappingB.originalColumn;
    if (cmp !== 0) {
      return cmp;
    }

    return strcmp(mappingA.name, mappingB.name);
  }
  exports.compareByGeneratedPositionsDeflated = compareByGeneratedPositionsDeflated;

  function strcmp(aStr1, aStr2) {
    if (aStr1 === aStr2) {
      return 0;
    }

    if (aStr1 === null) {
      return 1; // aStr2 !== null
    }

    if (aStr2 === null) {
      return -1; // aStr1 !== null
    }

    if (aStr1 > aStr2) {
      return 1;
    }

    return -1;
  }

  /**
   * Comparator between two mappings with inflated source and name strings where
   * the generated positions are compared.
   */
  function compareByGeneratedPositionsInflated(mappingA, mappingB) {
    var cmp = mappingA.generatedLine - mappingB.generatedLine;
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.generatedColumn - mappingB.generatedColumn;
    if (cmp !== 0) {
      return cmp;
    }

    cmp = strcmp(mappingA.source, mappingB.source);
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.originalLine - mappingB.originalLine;
    if (cmp !== 0) {
      return cmp;
    }

    cmp = mappingA.originalColumn - mappingB.originalColumn;
    if (cmp !== 0) {
      return cmp;
    }

    return strcmp(mappingA.name, mappingB.name);
  }
  exports.compareByGeneratedPositionsInflated = compareByGeneratedPositionsInflated;

  /**
   * Strip any JSON XSSI avoidance prefix from the string (as documented
   * in the source maps specification), and then parse the string as
   * JSON.
   */
  function parseSourceMapInput(str) {
    return JSON.parse(str.replace(/^\)]}'[^\n]*\n/, ''));
  }
  exports.parseSourceMapInput = parseSourceMapInput;

  /**
   * Compute the URL of a source given the the source root, the source's
   * URL, and the source map's URL.
   */
  function computeSourceURL(sourceRoot, sourceURL, sourceMapURL) {
    sourceURL = sourceURL || '';

    if (sourceRoot) {
      // This follows what Chrome does.
      if (sourceRoot[sourceRoot.length - 1] !== '/' && sourceURL[0] !== '/') {
        sourceRoot += '/';
      }
      // The spec says:
      //   Line 4: An optional source root, useful for relocating source
      //   files on a server or removing repeated values in the
      //   “sources” entry.  This value is prepended to the individual
      //   entries in the “source” field.
      sourceURL = sourceRoot + sourceURL;
    }

    // Historically, SourceMapConsumer did not take the sourceMapURL as
    // a parameter.  This mode is still somewhat supported, which is why
    // this code block is conditional.  However, it's preferable to pass
    // the source map URL to SourceMapConsumer, so that this function
    // can implement the source URL resolution algorithm as outlined in
    // the spec.  This block is basically the equivalent of:
    //    new URL(sourceURL, sourceMapURL).toString()
    // ... except it avoids using URL, which wasn't available in the
    // older releases of node still supported by this library.
    //
    // The spec says:
    //   If the sources are not absolute URLs after prepending of the
    //   “sourceRoot”, the sources are resolved relative to the
    //   SourceMap (like resolving script src in a html document).
    if (sourceMapURL) {
      var parsed = urlParse(sourceMapURL);
      if (!parsed) {
        throw new Error("sourceMapURL could not be parsed");
      }
      if (parsed.path) {
        // Strip the last path component, but keep the "/".
        var index = parsed.path.lastIndexOf('/');
        if (index >= 0) {
          parsed.path = parsed.path.substring(0, index + 1);
        }
      }
      sourceURL = join(urlGenerate(parsed), sourceURL);
    }

    return normalize(sourceURL);
  }
  exports.computeSourceURL = computeSourceURL;
  });

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */


  var has = Object.prototype.hasOwnProperty;
  var hasNativeMap = typeof Map !== "undefined";

  /**
   * A data structure which is a combination of an array and a set. Adding a new
   * member is O(1), testing for membership is O(1), and finding the index of an
   * element is O(1). Removing elements from the set is not supported. Only
   * strings are supported for membership.
   */
  function ArraySet() {
    this._array = [];
    this._set = hasNativeMap ? new Map() : Object.create(null);
  }

  /**
   * Static method for creating ArraySet instances from an existing array.
   */
  ArraySet.fromArray = function ArraySet_fromArray(aArray, aAllowDuplicates) {
    var set = new ArraySet();
    for (var i = 0, len = aArray.length; i < len; i++) {
      set.add(aArray[i], aAllowDuplicates);
    }
    return set;
  };

  /**
   * Return how many unique items are in this ArraySet. If duplicates have been
   * added, than those do not count towards the size.
   *
   * @returns Number
   */
  ArraySet.prototype.size = function ArraySet_size() {
    return hasNativeMap ? this._set.size : Object.getOwnPropertyNames(this._set).length;
  };

  /**
   * Add the given string to this set.
   *
   * @param String aStr
   */
  ArraySet.prototype.add = function ArraySet_add(aStr, aAllowDuplicates) {
    var sStr = hasNativeMap ? aStr : util.toSetString(aStr);
    var isDuplicate = hasNativeMap ? this.has(aStr) : has.call(this._set, sStr);
    var idx = this._array.length;
    if (!isDuplicate || aAllowDuplicates) {
      this._array.push(aStr);
    }
    if (!isDuplicate) {
      if (hasNativeMap) {
        this._set.set(aStr, idx);
      } else {
        this._set[sStr] = idx;
      }
    }
  };

  /**
   * Is the given string a member of this set?
   *
   * @param String aStr
   */
  ArraySet.prototype.has = function ArraySet_has(aStr) {
    if (hasNativeMap) {
      return this._set.has(aStr);
    } else {
      var sStr = util.toSetString(aStr);
      return has.call(this._set, sStr);
    }
  };

  /**
   * What is the index of the given string in the array?
   *
   * @param String aStr
   */
  ArraySet.prototype.indexOf = function ArraySet_indexOf(aStr) {
    if (hasNativeMap) {
      var idx = this._set.get(aStr);
      if (idx >= 0) {
          return idx;
      }
    } else {
      var sStr = util.toSetString(aStr);
      if (has.call(this._set, sStr)) {
        return this._set[sStr];
      }
    }

    throw new Error('"' + aStr + '" is not in the set.');
  };

  /**
   * What is the element at the given index?
   *
   * @param Number aIdx
   */
  ArraySet.prototype.at = function ArraySet_at(aIdx) {
    if (aIdx >= 0 && aIdx < this._array.length) {
      return this._array[aIdx];
    }
    throw new Error('No element indexed by ' + aIdx);
  };

  /**
   * Returns the array representation of this set (which has the proper indices
   * indicated by indexOf). Note that this is a copy of the internal array used
   * for storing the members so that no one can mess with internal state.
   */
  ArraySet.prototype.toArray = function ArraySet_toArray() {
    return this._array.slice();
  };

  var ArraySet_1 = ArraySet;

  var arraySet = {
  	ArraySet: ArraySet_1
  };

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2014 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */



  /**
   * Determine whether mappingB is after mappingA with respect to generated
   * position.
   */
  function generatedPositionAfter(mappingA, mappingB) {
    // Optimized for most common case
    var lineA = mappingA.generatedLine;
    var lineB = mappingB.generatedLine;
    var columnA = mappingA.generatedColumn;
    var columnB = mappingB.generatedColumn;
    return lineB > lineA || lineB == lineA && columnB >= columnA ||
           util.compareByGeneratedPositionsInflated(mappingA, mappingB) <= 0;
  }

  /**
   * A data structure to provide a sorted view of accumulated mappings in a
   * performance conscious manner. It trades a neglibable overhead in general
   * case for a large speedup in case of mappings being added in order.
   */
  function MappingList() {
    this._array = [];
    this._sorted = true;
    // Serves as infimum
    this._last = {generatedLine: -1, generatedColumn: 0};
  }

  /**
   * Iterate through internal items. This method takes the same arguments that
   * `Array.prototype.forEach` takes.
   *
   * NOTE: The order of the mappings is NOT guaranteed.
   */
  MappingList.prototype.unsortedForEach =
    function MappingList_forEach(aCallback, aThisArg) {
      this._array.forEach(aCallback, aThisArg);
    };

  /**
   * Add the given source mapping.
   *
   * @param Object aMapping
   */
  MappingList.prototype.add = function MappingList_add(aMapping) {
    if (generatedPositionAfter(this._last, aMapping)) {
      this._last = aMapping;
      this._array.push(aMapping);
    } else {
      this._sorted = false;
      this._array.push(aMapping);
    }
  };

  /**
   * Returns the flat, sorted array of mappings. The mappings are sorted by
   * generated position.
   *
   * WARNING: This method returns internal data without copying, for
   * performance. The return value must NOT be mutated, and should be treated as
   * an immutable borrow. If you want to take ownership, you must make your own
   * copy.
   */
  MappingList.prototype.toArray = function MappingList_toArray() {
    if (!this._sorted) {
      this._array.sort(util.compareByGeneratedPositionsInflated);
      this._sorted = true;
    }
    return this._array;
  };

  var MappingList_1 = MappingList;

  var mappingList = {
  	MappingList: MappingList_1
  };

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */



  var ArraySet$1 = arraySet.ArraySet;
  var MappingList$1 = mappingList.MappingList;

  /**
   * An instance of the SourceMapGenerator represents a source map which is
   * being built incrementally. You may pass an object with the following
   * properties:
   *
   *   - file: The filename of the generated source.
   *   - sourceRoot: A root for all relative URLs in this source map.
   */
  function SourceMapGenerator(aArgs) {
    if (!aArgs) {
      aArgs = {};
    }
    this._file = util.getArg(aArgs, 'file', null);
    this._sourceRoot = util.getArg(aArgs, 'sourceRoot', null);
    this._skipValidation = util.getArg(aArgs, 'skipValidation', false);
    this._sources = new ArraySet$1();
    this._names = new ArraySet$1();
    this._mappings = new MappingList$1();
    this._sourcesContents = null;
  }

  SourceMapGenerator.prototype._version = 3;

  /**
   * Creates a new SourceMapGenerator based on a SourceMapConsumer
   *
   * @param aSourceMapConsumer The SourceMap.
   */
  SourceMapGenerator.fromSourceMap =
    function SourceMapGenerator_fromSourceMap(aSourceMapConsumer) {
      var sourceRoot = aSourceMapConsumer.sourceRoot;
      var generator = new SourceMapGenerator({
        file: aSourceMapConsumer.file,
        sourceRoot: sourceRoot
      });
      aSourceMapConsumer.eachMapping(function (mapping) {
        var newMapping = {
          generated: {
            line: mapping.generatedLine,
            column: mapping.generatedColumn
          }
        };

        if (mapping.source != null) {
          newMapping.source = mapping.source;
          if (sourceRoot != null) {
            newMapping.source = util.relative(sourceRoot, newMapping.source);
          }

          newMapping.original = {
            line: mapping.originalLine,
            column: mapping.originalColumn
          };

          if (mapping.name != null) {
            newMapping.name = mapping.name;
          }
        }

        generator.addMapping(newMapping);
      });
      aSourceMapConsumer.sources.forEach(function (sourceFile) {
        var sourceRelative = sourceFile;
        if (sourceRoot !== null) {
          sourceRelative = util.relative(sourceRoot, sourceFile);
        }

        if (!generator._sources.has(sourceRelative)) {
          generator._sources.add(sourceRelative);
        }

        var content = aSourceMapConsumer.sourceContentFor(sourceFile);
        if (content != null) {
          generator.setSourceContent(sourceFile, content);
        }
      });
      return generator;
    };

  /**
   * Add a single mapping from original source line and column to the generated
   * source's line and column for this source map being created. The mapping
   * object should have the following properties:
   *
   *   - generated: An object with the generated line and column positions.
   *   - original: An object with the original line and column positions.
   *   - source: The original source file (relative to the sourceRoot).
   *   - name: An optional original token name for this mapping.
   */
  SourceMapGenerator.prototype.addMapping =
    function SourceMapGenerator_addMapping(aArgs) {
      var generated = util.getArg(aArgs, 'generated');
      var original = util.getArg(aArgs, 'original', null);
      var source = util.getArg(aArgs, 'source', null);
      var name = util.getArg(aArgs, 'name', null);

      if (!this._skipValidation) {
        this._validateMapping(generated, original, source, name);
      }

      if (source != null) {
        source = String(source);
        if (!this._sources.has(source)) {
          this._sources.add(source);
        }
      }

      if (name != null) {
        name = String(name);
        if (!this._names.has(name)) {
          this._names.add(name);
        }
      }

      this._mappings.add({
        generatedLine: generated.line,
        generatedColumn: generated.column,
        originalLine: original != null && original.line,
        originalColumn: original != null && original.column,
        source: source,
        name: name
      });
    };

  /**
   * Set the source content for a source file.
   */
  SourceMapGenerator.prototype.setSourceContent =
    function SourceMapGenerator_setSourceContent(aSourceFile, aSourceContent) {
      var source = aSourceFile;
      if (this._sourceRoot != null) {
        source = util.relative(this._sourceRoot, source);
      }

      if (aSourceContent != null) {
        // Add the source content to the _sourcesContents map.
        // Create a new _sourcesContents map if the property is null.
        if (!this._sourcesContents) {
          this._sourcesContents = Object.create(null);
        }
        this._sourcesContents[util.toSetString(source)] = aSourceContent;
      } else if (this._sourcesContents) {
        // Remove the source file from the _sourcesContents map.
        // If the _sourcesContents map is empty, set the property to null.
        delete this._sourcesContents[util.toSetString(source)];
        if (Object.keys(this._sourcesContents).length === 0) {
          this._sourcesContents = null;
        }
      }
    };

  /**
   * Applies the mappings of a sub-source-map for a specific source file to the
   * source map being generated. Each mapping to the supplied source file is
   * rewritten using the supplied source map. Note: The resolution for the
   * resulting mappings is the minimium of this map and the supplied map.
   *
   * @param aSourceMapConsumer The source map to be applied.
   * @param aSourceFile Optional. The filename of the source file.
   *        If omitted, SourceMapConsumer's file property will be used.
   * @param aSourceMapPath Optional. The dirname of the path to the source map
   *        to be applied. If relative, it is relative to the SourceMapConsumer.
   *        This parameter is needed when the two source maps aren't in the same
   *        directory, and the source map to be applied contains relative source
   *        paths. If so, those relative source paths need to be rewritten
   *        relative to the SourceMapGenerator.
   */
  SourceMapGenerator.prototype.applySourceMap =
    function SourceMapGenerator_applySourceMap(aSourceMapConsumer, aSourceFile, aSourceMapPath) {
      var sourceFile = aSourceFile;
      // If aSourceFile is omitted, we will use the file property of the SourceMap
      if (aSourceFile == null) {
        if (aSourceMapConsumer.file == null) {
          throw new Error(
            'SourceMapGenerator.prototype.applySourceMap requires either an explicit source file, ' +
            'or the source map\'s "file" property. Both were omitted.'
          );
        }
        sourceFile = aSourceMapConsumer.file;
      }
      var sourceRoot = this._sourceRoot;
      // Make "sourceFile" relative if an absolute Url is passed.
      if (sourceRoot != null) {
        sourceFile = util.relative(sourceRoot, sourceFile);
      }
      // Applying the SourceMap can add and remove items from the sources and
      // the names array.
      var newSources = new ArraySet$1();
      var newNames = new ArraySet$1();

      // Find mappings for the "sourceFile"
      this._mappings.unsortedForEach(function (mapping) {
        if (mapping.source === sourceFile && mapping.originalLine != null) {
          // Check if it can be mapped by the source map, then update the mapping.
          var original = aSourceMapConsumer.originalPositionFor({
            line: mapping.originalLine,
            column: mapping.originalColumn
          });
          if (original.source != null) {
            // Copy mapping
            mapping.source = original.source;
            if (aSourceMapPath != null) {
              mapping.source = util.join(aSourceMapPath, mapping.source);
            }
            if (sourceRoot != null) {
              mapping.source = util.relative(sourceRoot, mapping.source);
            }
            mapping.originalLine = original.line;
            mapping.originalColumn = original.column;
            if (original.name != null) {
              mapping.name = original.name;
            }
          }
        }

        var source = mapping.source;
        if (source != null && !newSources.has(source)) {
          newSources.add(source);
        }

        var name = mapping.name;
        if (name != null && !newNames.has(name)) {
          newNames.add(name);
        }

      }, this);
      this._sources = newSources;
      this._names = newNames;

      // Copy sourcesContents of applied map.
      aSourceMapConsumer.sources.forEach(function (sourceFile) {
        var content = aSourceMapConsumer.sourceContentFor(sourceFile);
        if (content != null) {
          if (aSourceMapPath != null) {
            sourceFile = util.join(aSourceMapPath, sourceFile);
          }
          if (sourceRoot != null) {
            sourceFile = util.relative(sourceRoot, sourceFile);
          }
          this.setSourceContent(sourceFile, content);
        }
      }, this);
    };

  /**
   * A mapping can have one of the three levels of data:
   *
   *   1. Just the generated position.
   *   2. The Generated position, original position, and original source.
   *   3. Generated and original position, original source, as well as a name
   *      token.
   *
   * To maintain consistency, we validate that any new mapping being added falls
   * in to one of these categories.
   */
  SourceMapGenerator.prototype._validateMapping =
    function SourceMapGenerator_validateMapping(aGenerated, aOriginal, aSource,
                                                aName) {
      // When aOriginal is truthy but has empty values for .line and .column,
      // it is most likely a programmer error. In this case we throw a very
      // specific error message to try to guide them the right way.
      // For example: https://github.com/Polymer/polymer-bundler/pull/519
      if (aOriginal && typeof aOriginal.line !== 'number' && typeof aOriginal.column !== 'number') {
          throw new Error(
              'original.line and original.column are not numbers -- you probably meant to omit ' +
              'the original mapping entirely and only map the generated position. If so, pass ' +
              'null for the original mapping instead of an object with empty or null values.'
          );
      }

      if (aGenerated && 'line' in aGenerated && 'column' in aGenerated
          && aGenerated.line > 0 && aGenerated.column >= 0
          && !aOriginal && !aSource && !aName) {
        // Case 1.
        return;
      }
      else if (aGenerated && 'line' in aGenerated && 'column' in aGenerated
               && aOriginal && 'line' in aOriginal && 'column' in aOriginal
               && aGenerated.line > 0 && aGenerated.column >= 0
               && aOriginal.line > 0 && aOriginal.column >= 0
               && aSource) {
        // Cases 2 and 3.
        return;
      }
      else {
        throw new Error('Invalid mapping: ' + JSON.stringify({
          generated: aGenerated,
          source: aSource,
          original: aOriginal,
          name: aName
        }));
      }
    };

  /**
   * Serialize the accumulated mappings in to the stream of base 64 VLQs
   * specified by the source map format.
   */
  SourceMapGenerator.prototype._serializeMappings =
    function SourceMapGenerator_serializeMappings() {
      var previousGeneratedColumn = 0;
      var previousGeneratedLine = 1;
      var previousOriginalColumn = 0;
      var previousOriginalLine = 0;
      var previousName = 0;
      var previousSource = 0;
      var result = '';
      var next;
      var mapping;
      var nameIdx;
      var sourceIdx;

      var mappings = this._mappings.toArray();
      for (var i = 0, len = mappings.length; i < len; i++) {
        mapping = mappings[i];
        next = '';

        if (mapping.generatedLine !== previousGeneratedLine) {
          previousGeneratedColumn = 0;
          while (mapping.generatedLine !== previousGeneratedLine) {
            next += ';';
            previousGeneratedLine++;
          }
        }
        else {
          if (i > 0) {
            if (!util.compareByGeneratedPositionsInflated(mapping, mappings[i - 1])) {
              continue;
            }
            next += ',';
          }
        }

        next += base64Vlq.encode(mapping.generatedColumn
                                   - previousGeneratedColumn);
        previousGeneratedColumn = mapping.generatedColumn;

        if (mapping.source != null) {
          sourceIdx = this._sources.indexOf(mapping.source);
          next += base64Vlq.encode(sourceIdx - previousSource);
          previousSource = sourceIdx;

          // lines are stored 0-based in SourceMap spec version 3
          next += base64Vlq.encode(mapping.originalLine - 1
                                     - previousOriginalLine);
          previousOriginalLine = mapping.originalLine - 1;

          next += base64Vlq.encode(mapping.originalColumn
                                     - previousOriginalColumn);
          previousOriginalColumn = mapping.originalColumn;

          if (mapping.name != null) {
            nameIdx = this._names.indexOf(mapping.name);
            next += base64Vlq.encode(nameIdx - previousName);
            previousName = nameIdx;
          }
        }

        result += next;
      }

      return result;
    };

  SourceMapGenerator.prototype._generateSourcesContent =
    function SourceMapGenerator_generateSourcesContent(aSources, aSourceRoot) {
      return aSources.map(function (source) {
        if (!this._sourcesContents) {
          return null;
        }
        if (aSourceRoot != null) {
          source = util.relative(aSourceRoot, source);
        }
        var key = util.toSetString(source);
        return Object.prototype.hasOwnProperty.call(this._sourcesContents, key)
          ? this._sourcesContents[key]
          : null;
      }, this);
    };

  /**
   * Externalize the source map.
   */
  SourceMapGenerator.prototype.toJSON =
    function SourceMapGenerator_toJSON() {
      var map = {
        version: this._version,
        sources: this._sources.toArray(),
        names: this._names.toArray(),
        mappings: this._serializeMappings()
      };
      if (this._file != null) {
        map.file = this._file;
      }
      if (this._sourceRoot != null) {
        map.sourceRoot = this._sourceRoot;
      }
      if (this._sourcesContents) {
        map.sourcesContent = this._generateSourcesContent(map.sources, map.sourceRoot);
      }

      return map;
    };

  /**
   * Render the source map being generated to a string.
   */
  SourceMapGenerator.prototype.toString =
    function SourceMapGenerator_toString() {
      return JSON.stringify(this.toJSON());
    };

  var SourceMapGenerator_1 = SourceMapGenerator;

  var sourceMapGenerator = {
  	SourceMapGenerator: SourceMapGenerator_1
  };

  var binarySearch = createCommonjsModule(function (module, exports) {
  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */

  exports.GREATEST_LOWER_BOUND = 1;
  exports.LEAST_UPPER_BOUND = 2;

  /**
   * Recursive implementation of binary search.
   *
   * @param aLow Indices here and lower do not contain the needle.
   * @param aHigh Indices here and higher do not contain the needle.
   * @param aNeedle The element being searched for.
   * @param aHaystack The non-empty array being searched.
   * @param aCompare Function which takes two elements and returns -1, 0, or 1.
   * @param aBias Either 'binarySearch.GREATEST_LOWER_BOUND' or
   *     'binarySearch.LEAST_UPPER_BOUND'. Specifies whether to return the
   *     closest element that is smaller than or greater than the one we are
   *     searching for, respectively, if the exact element cannot be found.
   */
  function recursiveSearch(aLow, aHigh, aNeedle, aHaystack, aCompare, aBias) {
    // This function terminates when one of the following is true:
    //
    //   1. We find the exact element we are looking for.
    //
    //   2. We did not find the exact element, but we can return the index of
    //      the next-closest element.
    //
    //   3. We did not find the exact element, and there is no next-closest
    //      element than the one we are searching for, so we return -1.
    var mid = Math.floor((aHigh - aLow) / 2) + aLow;
    var cmp = aCompare(aNeedle, aHaystack[mid], true);
    if (cmp === 0) {
      // Found the element we are looking for.
      return mid;
    }
    else if (cmp > 0) {
      // Our needle is greater than aHaystack[mid].
      if (aHigh - mid > 1) {
        // The element is in the upper half.
        return recursiveSearch(mid, aHigh, aNeedle, aHaystack, aCompare, aBias);
      }

      // The exact needle element was not found in this haystack. Determine if
      // we are in termination case (3) or (2) and return the appropriate thing.
      if (aBias == exports.LEAST_UPPER_BOUND) {
        return aHigh < aHaystack.length ? aHigh : -1;
      } else {
        return mid;
      }
    }
    else {
      // Our needle is less than aHaystack[mid].
      if (mid - aLow > 1) {
        // The element is in the lower half.
        return recursiveSearch(aLow, mid, aNeedle, aHaystack, aCompare, aBias);
      }

      // we are in termination case (3) or (2) and return the appropriate thing.
      if (aBias == exports.LEAST_UPPER_BOUND) {
        return mid;
      } else {
        return aLow < 0 ? -1 : aLow;
      }
    }
  }

  /**
   * This is an implementation of binary search which will always try and return
   * the index of the closest element if there is no exact hit. This is because
   * mappings between original and generated line/col pairs are single points,
   * and there is an implicit region between each of them, so a miss just means
   * that you aren't on the very start of a region.
   *
   * @param aNeedle The element you are looking for.
   * @param aHaystack The array that is being searched.
   * @param aCompare A function which takes the needle and an element in the
   *     array and returns -1, 0, or 1 depending on whether the needle is less
   *     than, equal to, or greater than the element, respectively.
   * @param aBias Either 'binarySearch.GREATEST_LOWER_BOUND' or
   *     'binarySearch.LEAST_UPPER_BOUND'. Specifies whether to return the
   *     closest element that is smaller than or greater than the one we are
   *     searching for, respectively, if the exact element cannot be found.
   *     Defaults to 'binarySearch.GREATEST_LOWER_BOUND'.
   */
  exports.search = function search(aNeedle, aHaystack, aCompare, aBias) {
    if (aHaystack.length === 0) {
      return -1;
    }

    var index = recursiveSearch(-1, aHaystack.length, aNeedle, aHaystack,
                                aCompare, aBias || exports.GREATEST_LOWER_BOUND);
    if (index < 0) {
      return -1;
    }

    // We have found either the exact element, or the next-closest element than
    // the one we are searching for. However, there may be more than one such
    // element. Make sure we always return the smallest of these.
    while (index - 1 >= 0) {
      if (aCompare(aHaystack[index], aHaystack[index - 1], true) !== 0) {
        break;
      }
      --index;
    }

    return index;
  };
  });

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */

  // It turns out that some (most?) JavaScript engines don't self-host
  // `Array.prototype.sort`. This makes sense because C++ will likely remain
  // faster than JS when doing raw CPU-intensive sorting. However, when using a
  // custom comparator function, calling back and forth between the VM's C++ and
  // JIT'd JS is rather slow *and* loses JIT type information, resulting in
  // worse generated code for the comparator function than would be optimal. In
  // fact, when sorting with a comparator, these costs outweigh the benefits of
  // sorting in C++. By using our own JS-implemented Quick Sort (below), we get
  // a ~3500ms mean speed-up in `bench/bench.html`.

  /**
   * Swap the elements indexed by `x` and `y` in the array `ary`.
   *
   * @param {Array} ary
   *        The array.
   * @param {Number} x
   *        The index of the first item.
   * @param {Number} y
   *        The index of the second item.
   */
  function swap(ary, x, y) {
    var temp = ary[x];
    ary[x] = ary[y];
    ary[y] = temp;
  }

  /**
   * Returns a random integer within the range `low .. high` inclusive.
   *
   * @param {Number} low
   *        The lower bound on the range.
   * @param {Number} high
   *        The upper bound on the range.
   */
  function randomIntInRange(low, high) {
    return Math.round(low + (Math.random() * (high - low)));
  }

  /**
   * The Quick Sort algorithm.
   *
   * @param {Array} ary
   *        An array to sort.
   * @param {function} comparator
   *        Function to use to compare two items.
   * @param {Number} p
   *        Start index of the array
   * @param {Number} r
   *        End index of the array
   */
  function doQuickSort(ary, comparator, p, r) {
    // If our lower bound is less than our upper bound, we (1) partition the
    // array into two pieces and (2) recurse on each half. If it is not, this is
    // the empty array and our base case.

    if (p < r) {
      // (1) Partitioning.
      //
      // The partitioning chooses a pivot between `p` and `r` and moves all
      // elements that are less than or equal to the pivot to the before it, and
      // all the elements that are greater than it after it. The effect is that
      // once partition is done, the pivot is in the exact place it will be when
      // the array is put in sorted order, and it will not need to be moved
      // again. This runs in O(n) time.

      // Always choose a random pivot so that an input array which is reverse
      // sorted does not cause O(n^2) running time.
      var pivotIndex = randomIntInRange(p, r);
      var i = p - 1;

      swap(ary, pivotIndex, r);
      var pivot = ary[r];

      // Immediately after `j` is incremented in this loop, the following hold
      // true:
      //
      //   * Every element in `ary[p .. i]` is less than or equal to the pivot.
      //
      //   * Every element in `ary[i+1 .. j-1]` is greater than the pivot.
      for (var j = p; j < r; j++) {
        if (comparator(ary[j], pivot) <= 0) {
          i += 1;
          swap(ary, i, j);
        }
      }

      swap(ary, i + 1, j);
      var q = i + 1;

      // (2) Recurse on each half.

      doQuickSort(ary, comparator, p, q - 1);
      doQuickSort(ary, comparator, q + 1, r);
    }
  }

  /**
   * Sort the given array in-place with the given comparator function.
   *
   * @param {Array} ary
   *        An array to sort.
   * @param {function} comparator
   *        Function to use to compare two items.
   */
  var quickSort_1 = function (ary, comparator) {
    doQuickSort(ary, comparator, 0, ary.length - 1);
  };

  var quickSort = {
  	quickSort: quickSort_1
  };

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */



  var ArraySet$2 = arraySet.ArraySet;

  var quickSort$1 = quickSort.quickSort;

  function SourceMapConsumer(aSourceMap, aSourceMapURL) {
    var sourceMap = aSourceMap;
    if (typeof aSourceMap === 'string') {
      sourceMap = util.parseSourceMapInput(aSourceMap);
    }

    return sourceMap.sections != null
      ? new IndexedSourceMapConsumer(sourceMap, aSourceMapURL)
      : new BasicSourceMapConsumer(sourceMap, aSourceMapURL);
  }

  SourceMapConsumer.fromSourceMap = function(aSourceMap, aSourceMapURL) {
    return BasicSourceMapConsumer.fromSourceMap(aSourceMap, aSourceMapURL);
  };

  /**
   * The version of the source mapping spec that we are consuming.
   */
  SourceMapConsumer.prototype._version = 3;

  // `__generatedMappings` and `__originalMappings` are arrays that hold the
  // parsed mapping coordinates from the source map's "mappings" attribute. They
  // are lazily instantiated, accessed via the `_generatedMappings` and
  // `_originalMappings` getters respectively, and we only parse the mappings
  // and create these arrays once queried for a source location. We jump through
  // these hoops because there can be many thousands of mappings, and parsing
  // them is expensive, so we only want to do it if we must.
  //
  // Each object in the arrays is of the form:
  //
  //     {
  //       generatedLine: The line number in the generated code,
  //       generatedColumn: The column number in the generated code,
  //       source: The path to the original source file that generated this
  //               chunk of code,
  //       originalLine: The line number in the original source that
  //                     corresponds to this chunk of generated code,
  //       originalColumn: The column number in the original source that
  //                       corresponds to this chunk of generated code,
  //       name: The name of the original symbol which generated this chunk of
  //             code.
  //     }
  //
  // All properties except for `generatedLine` and `generatedColumn` can be
  // `null`.
  //
  // `_generatedMappings` is ordered by the generated positions.
  //
  // `_originalMappings` is ordered by the original positions.

  SourceMapConsumer.prototype.__generatedMappings = null;
  Object.defineProperty(SourceMapConsumer.prototype, '_generatedMappings', {
    configurable: true,
    enumerable: true,
    get: function () {
      if (!this.__generatedMappings) {
        this._parseMappings(this._mappings, this.sourceRoot);
      }

      return this.__generatedMappings;
    }
  });

  SourceMapConsumer.prototype.__originalMappings = null;
  Object.defineProperty(SourceMapConsumer.prototype, '_originalMappings', {
    configurable: true,
    enumerable: true,
    get: function () {
      if (!this.__originalMappings) {
        this._parseMappings(this._mappings, this.sourceRoot);
      }

      return this.__originalMappings;
    }
  });

  SourceMapConsumer.prototype._charIsMappingSeparator =
    function SourceMapConsumer_charIsMappingSeparator(aStr, index) {
      var c = aStr.charAt(index);
      return c === ";" || c === ",";
    };

  /**
   * Parse the mappings in a string in to a data structure which we can easily
   * query (the ordered arrays in the `this.__generatedMappings` and
   * `this.__originalMappings` properties).
   */
  SourceMapConsumer.prototype._parseMappings =
    function SourceMapConsumer_parseMappings(aStr, aSourceRoot) {
      throw new Error("Subclasses must implement _parseMappings");
    };

  SourceMapConsumer.GENERATED_ORDER = 1;
  SourceMapConsumer.ORIGINAL_ORDER = 2;

  SourceMapConsumer.GREATEST_LOWER_BOUND = 1;
  SourceMapConsumer.LEAST_UPPER_BOUND = 2;

  /**
   * Iterate over each mapping between an original source/line/column and a
   * generated line/column in this source map.
   *
   * @param Function aCallback
   *        The function that is called with each mapping.
   * @param Object aContext
   *        Optional. If specified, this object will be the value of `this` every
   *        time that `aCallback` is called.
   * @param aOrder
   *        Either `SourceMapConsumer.GENERATED_ORDER` or
   *        `SourceMapConsumer.ORIGINAL_ORDER`. Specifies whether you want to
   *        iterate over the mappings sorted by the generated file's line/column
   *        order or the original's source/line/column order, respectively. Defaults to
   *        `SourceMapConsumer.GENERATED_ORDER`.
   */
  SourceMapConsumer.prototype.eachMapping =
    function SourceMapConsumer_eachMapping(aCallback, aContext, aOrder) {
      var context = aContext || null;
      var order = aOrder || SourceMapConsumer.GENERATED_ORDER;

      var mappings;
      switch (order) {
      case SourceMapConsumer.GENERATED_ORDER:
        mappings = this._generatedMappings;
        break;
      case SourceMapConsumer.ORIGINAL_ORDER:
        mappings = this._originalMappings;
        break;
      default:
        throw new Error("Unknown order of iteration.");
      }

      var sourceRoot = this.sourceRoot;
      mappings.map(function (mapping) {
        var source = mapping.source === null ? null : this._sources.at(mapping.source);
        source = util.computeSourceURL(sourceRoot, source, this._sourceMapURL);
        return {
          source: source,
          generatedLine: mapping.generatedLine,
          generatedColumn: mapping.generatedColumn,
          originalLine: mapping.originalLine,
          originalColumn: mapping.originalColumn,
          name: mapping.name === null ? null : this._names.at(mapping.name)
        };
      }, this).forEach(aCallback, context);
    };

  /**
   * Returns all generated line and column information for the original source,
   * line, and column provided. If no column is provided, returns all mappings
   * corresponding to a either the line we are searching for or the next
   * closest line that has any mappings. Otherwise, returns all mappings
   * corresponding to the given line and either the column we are searching for
   * or the next closest column that has any offsets.
   *
   * The only argument is an object with the following properties:
   *
   *   - source: The filename of the original source.
   *   - line: The line number in the original source.  The line number is 1-based.
   *   - column: Optional. the column number in the original source.
   *    The column number is 0-based.
   *
   * and an array of objects is returned, each with the following properties:
   *
   *   - line: The line number in the generated source, or null.  The
   *    line number is 1-based.
   *   - column: The column number in the generated source, or null.
   *    The column number is 0-based.
   */
  SourceMapConsumer.prototype.allGeneratedPositionsFor =
    function SourceMapConsumer_allGeneratedPositionsFor(aArgs) {
      var line = util.getArg(aArgs, 'line');

      // When there is no exact match, BasicSourceMapConsumer.prototype._findMapping
      // returns the index of the closest mapping less than the needle. By
      // setting needle.originalColumn to 0, we thus find the last mapping for
      // the given line, provided such a mapping exists.
      var needle = {
        source: util.getArg(aArgs, 'source'),
        originalLine: line,
        originalColumn: util.getArg(aArgs, 'column', 0)
      };

      needle.source = this._findSourceIndex(needle.source);
      if (needle.source < 0) {
        return [];
      }

      var mappings = [];

      var index = this._findMapping(needle,
                                    this._originalMappings,
                                    "originalLine",
                                    "originalColumn",
                                    util.compareByOriginalPositions,
                                    binarySearch.LEAST_UPPER_BOUND);
      if (index >= 0) {
        var mapping = this._originalMappings[index];

        if (aArgs.column === undefined) {
          var originalLine = mapping.originalLine;

          // Iterate until either we run out of mappings, or we run into
          // a mapping for a different line than the one we found. Since
          // mappings are sorted, this is guaranteed to find all mappings for
          // the line we found.
          while (mapping && mapping.originalLine === originalLine) {
            mappings.push({
              line: util.getArg(mapping, 'generatedLine', null),
              column: util.getArg(mapping, 'generatedColumn', null),
              lastColumn: util.getArg(mapping, 'lastGeneratedColumn', null)
            });

            mapping = this._originalMappings[++index];
          }
        } else {
          var originalColumn = mapping.originalColumn;

          // Iterate until either we run out of mappings, or we run into
          // a mapping for a different line than the one we were searching for.
          // Since mappings are sorted, this is guaranteed to find all mappings for
          // the line we are searching for.
          while (mapping &&
                 mapping.originalLine === line &&
                 mapping.originalColumn == originalColumn) {
            mappings.push({
              line: util.getArg(mapping, 'generatedLine', null),
              column: util.getArg(mapping, 'generatedColumn', null),
              lastColumn: util.getArg(mapping, 'lastGeneratedColumn', null)
            });

            mapping = this._originalMappings[++index];
          }
        }
      }

      return mappings;
    };

  var SourceMapConsumer_1 = SourceMapConsumer;

  /**
   * A BasicSourceMapConsumer instance represents a parsed source map which we can
   * query for information about the original file positions by giving it a file
   * position in the generated source.
   *
   * The first parameter is the raw source map (either as a JSON string, or
   * already parsed to an object). According to the spec, source maps have the
   * following attributes:
   *
   *   - version: Which version of the source map spec this map is following.
   *   - sources: An array of URLs to the original source files.
   *   - names: An array of identifiers which can be referrenced by individual mappings.
   *   - sourceRoot: Optional. The URL root from which all sources are relative.
   *   - sourcesContent: Optional. An array of contents of the original source files.
   *   - mappings: A string of base64 VLQs which contain the actual mappings.
   *   - file: Optional. The generated file this source map is associated with.
   *
   * Here is an example source map, taken from the source map spec[0]:
   *
   *     {
   *       version : 3,
   *       file: "out.js",
   *       sourceRoot : "",
   *       sources: ["foo.js", "bar.js"],
   *       names: ["src", "maps", "are", "fun"],
   *       mappings: "AA,AB;;ABCDE;"
   *     }
   *
   * The second parameter, if given, is a string whose value is the URL
   * at which the source map was found.  This URL is used to compute the
   * sources array.
   *
   * [0]: https://docs.google.com/document/d/1U1RGAehQwRypUTovF1KRlpiOFze0b-_2gc6fAH0KY0k/edit?pli=1#
   */
  function BasicSourceMapConsumer(aSourceMap, aSourceMapURL) {
    var sourceMap = aSourceMap;
    if (typeof aSourceMap === 'string') {
      sourceMap = util.parseSourceMapInput(aSourceMap);
    }

    var version = util.getArg(sourceMap, 'version');
    var sources = util.getArg(sourceMap, 'sources');
    // Sass 3.3 leaves out the 'names' array, so we deviate from the spec (which
    // requires the array) to play nice here.
    var names = util.getArg(sourceMap, 'names', []);
    var sourceRoot = util.getArg(sourceMap, 'sourceRoot', null);
    var sourcesContent = util.getArg(sourceMap, 'sourcesContent', null);
    var mappings = util.getArg(sourceMap, 'mappings');
    var file = util.getArg(sourceMap, 'file', null);

    // Once again, Sass deviates from the spec and supplies the version as a
    // string rather than a number, so we use loose equality checking here.
    if (version != this._version) {
      throw new Error('Unsupported version: ' + version);
    }

    if (sourceRoot) {
      sourceRoot = util.normalize(sourceRoot);
    }

    sources = sources
      .map(String)
      // Some source maps produce relative source paths like "./foo.js" instead of
      // "foo.js".  Normalize these first so that future comparisons will succeed.
      // See bugzil.la/1090768.
      .map(util.normalize)
      // Always ensure that absolute sources are internally stored relative to
      // the source root, if the source root is absolute. Not doing this would
      // be particularly problematic when the source root is a prefix of the
      // source (valid, but why??). See github issue #199 and bugzil.la/1188982.
      .map(function (source) {
        return sourceRoot && util.isAbsolute(sourceRoot) && util.isAbsolute(source)
          ? util.relative(sourceRoot, source)
          : source;
      });

    // Pass `true` below to allow duplicate names and sources. While source maps
    // are intended to be compressed and deduplicated, the TypeScript compiler
    // sometimes generates source maps with duplicates in them. See Github issue
    // #72 and bugzil.la/889492.
    this._names = ArraySet$2.fromArray(names.map(String), true);
    this._sources = ArraySet$2.fromArray(sources, true);

    this._absoluteSources = this._sources.toArray().map(function (s) {
      return util.computeSourceURL(sourceRoot, s, aSourceMapURL);
    });

    this.sourceRoot = sourceRoot;
    this.sourcesContent = sourcesContent;
    this._mappings = mappings;
    this._sourceMapURL = aSourceMapURL;
    this.file = file;
  }

  BasicSourceMapConsumer.prototype = Object.create(SourceMapConsumer.prototype);
  BasicSourceMapConsumer.prototype.consumer = SourceMapConsumer;

  /**
   * Utility function to find the index of a source.  Returns -1 if not
   * found.
   */
  BasicSourceMapConsumer.prototype._findSourceIndex = function(aSource) {
    var relativeSource = aSource;
    if (this.sourceRoot != null) {
      relativeSource = util.relative(this.sourceRoot, relativeSource);
    }

    if (this._sources.has(relativeSource)) {
      return this._sources.indexOf(relativeSource);
    }

    // Maybe aSource is an absolute URL as returned by |sources|.  In
    // this case we can't simply undo the transform.
    var i;
    for (i = 0; i < this._absoluteSources.length; ++i) {
      if (this._absoluteSources[i] == aSource) {
        return i;
      }
    }

    return -1;
  };

  /**
   * Create a BasicSourceMapConsumer from a SourceMapGenerator.
   *
   * @param SourceMapGenerator aSourceMap
   *        The source map that will be consumed.
   * @param String aSourceMapURL
   *        The URL at which the source map can be found (optional)
   * @returns BasicSourceMapConsumer
   */
  BasicSourceMapConsumer.fromSourceMap =
    function SourceMapConsumer_fromSourceMap(aSourceMap, aSourceMapURL) {
      var smc = Object.create(BasicSourceMapConsumer.prototype);

      var names = smc._names = ArraySet$2.fromArray(aSourceMap._names.toArray(), true);
      var sources = smc._sources = ArraySet$2.fromArray(aSourceMap._sources.toArray(), true);
      smc.sourceRoot = aSourceMap._sourceRoot;
      smc.sourcesContent = aSourceMap._generateSourcesContent(smc._sources.toArray(),
                                                              smc.sourceRoot);
      smc.file = aSourceMap._file;
      smc._sourceMapURL = aSourceMapURL;
      smc._absoluteSources = smc._sources.toArray().map(function (s) {
        return util.computeSourceURL(smc.sourceRoot, s, aSourceMapURL);
      });

      // Because we are modifying the entries (by converting string sources and
      // names to indices into the sources and names ArraySets), we have to make
      // a copy of the entry or else bad things happen. Shared mutable state
      // strikes again! See github issue #191.

      var generatedMappings = aSourceMap._mappings.toArray().slice();
      var destGeneratedMappings = smc.__generatedMappings = [];
      var destOriginalMappings = smc.__originalMappings = [];

      for (var i = 0, length = generatedMappings.length; i < length; i++) {
        var srcMapping = generatedMappings[i];
        var destMapping = new Mapping;
        destMapping.generatedLine = srcMapping.generatedLine;
        destMapping.generatedColumn = srcMapping.generatedColumn;

        if (srcMapping.source) {
          destMapping.source = sources.indexOf(srcMapping.source);
          destMapping.originalLine = srcMapping.originalLine;
          destMapping.originalColumn = srcMapping.originalColumn;

          if (srcMapping.name) {
            destMapping.name = names.indexOf(srcMapping.name);
          }

          destOriginalMappings.push(destMapping);
        }

        destGeneratedMappings.push(destMapping);
      }

      quickSort$1(smc.__originalMappings, util.compareByOriginalPositions);

      return smc;
    };

  /**
   * The version of the source mapping spec that we are consuming.
   */
  BasicSourceMapConsumer.prototype._version = 3;

  /**
   * The list of original sources.
   */
  Object.defineProperty(BasicSourceMapConsumer.prototype, 'sources', {
    get: function () {
      return this._absoluteSources.slice();
    }
  });

  /**
   * Provide the JIT with a nice shape / hidden class.
   */
  function Mapping() {
    this.generatedLine = 0;
    this.generatedColumn = 0;
    this.source = null;
    this.originalLine = null;
    this.originalColumn = null;
    this.name = null;
  }

  /**
   * Parse the mappings in a string in to a data structure which we can easily
   * query (the ordered arrays in the `this.__generatedMappings` and
   * `this.__originalMappings` properties).
   */
  BasicSourceMapConsumer.prototype._parseMappings =
    function SourceMapConsumer_parseMappings(aStr, aSourceRoot) {
      var generatedLine = 1;
      var previousGeneratedColumn = 0;
      var previousOriginalLine = 0;
      var previousOriginalColumn = 0;
      var previousSource = 0;
      var previousName = 0;
      var length = aStr.length;
      var index = 0;
      var cachedSegments = {};
      var temp = {};
      var originalMappings = [];
      var generatedMappings = [];
      var mapping, str, segment, end, value;

      while (index < length) {
        if (aStr.charAt(index) === ';') {
          generatedLine++;
          index++;
          previousGeneratedColumn = 0;
        }
        else if (aStr.charAt(index) === ',') {
          index++;
        }
        else {
          mapping = new Mapping();
          mapping.generatedLine = generatedLine;

          // Because each offset is encoded relative to the previous one,
          // many segments often have the same encoding. We can exploit this
          // fact by caching the parsed variable length fields of each segment,
          // allowing us to avoid a second parse if we encounter the same
          // segment again.
          for (end = index; end < length; end++) {
            if (this._charIsMappingSeparator(aStr, end)) {
              break;
            }
          }
          str = aStr.slice(index, end);

          segment = cachedSegments[str];
          if (segment) {
            index += str.length;
          } else {
            segment = [];
            while (index < end) {
              base64Vlq.decode(aStr, index, temp);
              value = temp.value;
              index = temp.rest;
              segment.push(value);
            }

            if (segment.length === 2) {
              throw new Error('Found a source, but no line and column');
            }

            if (segment.length === 3) {
              throw new Error('Found a source and line, but no column');
            }

            cachedSegments[str] = segment;
          }

          // Generated column.
          mapping.generatedColumn = previousGeneratedColumn + segment[0];
          previousGeneratedColumn = mapping.generatedColumn;

          if (segment.length > 1) {
            // Original source.
            mapping.source = previousSource + segment[1];
            previousSource += segment[1];

            // Original line.
            mapping.originalLine = previousOriginalLine + segment[2];
            previousOriginalLine = mapping.originalLine;
            // Lines are stored 0-based
            mapping.originalLine += 1;

            // Original column.
            mapping.originalColumn = previousOriginalColumn + segment[3];
            previousOriginalColumn = mapping.originalColumn;

            if (segment.length > 4) {
              // Original name.
              mapping.name = previousName + segment[4];
              previousName += segment[4];
            }
          }

          generatedMappings.push(mapping);
          if (typeof mapping.originalLine === 'number') {
            originalMappings.push(mapping);
          }
        }
      }

      quickSort$1(generatedMappings, util.compareByGeneratedPositionsDeflated);
      this.__generatedMappings = generatedMappings;

      quickSort$1(originalMappings, util.compareByOriginalPositions);
      this.__originalMappings = originalMappings;
    };

  /**
   * Find the mapping that best matches the hypothetical "needle" mapping that
   * we are searching for in the given "haystack" of mappings.
   */
  BasicSourceMapConsumer.prototype._findMapping =
    function SourceMapConsumer_findMapping(aNeedle, aMappings, aLineName,
                                           aColumnName, aComparator, aBias) {
      // To return the position we are searching for, we must first find the
      // mapping for the given position and then return the opposite position it
      // points to. Because the mappings are sorted, we can use binary search to
      // find the best mapping.

      if (aNeedle[aLineName] <= 0) {
        throw new TypeError('Line must be greater than or equal to 1, got '
                            + aNeedle[aLineName]);
      }
      if (aNeedle[aColumnName] < 0) {
        throw new TypeError('Column must be greater than or equal to 0, got '
                            + aNeedle[aColumnName]);
      }

      return binarySearch.search(aNeedle, aMappings, aComparator, aBias);
    };

  /**
   * Compute the last column for each generated mapping. The last column is
   * inclusive.
   */
  BasicSourceMapConsumer.prototype.computeColumnSpans =
    function SourceMapConsumer_computeColumnSpans() {
      for (var index = 0; index < this._generatedMappings.length; ++index) {
        var mapping = this._generatedMappings[index];

        // Mappings do not contain a field for the last generated columnt. We
        // can come up with an optimistic estimate, however, by assuming that
        // mappings are contiguous (i.e. given two consecutive mappings, the
        // first mapping ends where the second one starts).
        if (index + 1 < this._generatedMappings.length) {
          var nextMapping = this._generatedMappings[index + 1];

          if (mapping.generatedLine === nextMapping.generatedLine) {
            mapping.lastGeneratedColumn = nextMapping.generatedColumn - 1;
            continue;
          }
        }

        // The last mapping for each line spans the entire line.
        mapping.lastGeneratedColumn = Infinity;
      }
    };

  /**
   * Returns the original source, line, and column information for the generated
   * source's line and column positions provided. The only argument is an object
   * with the following properties:
   *
   *   - line: The line number in the generated source.  The line number
   *     is 1-based.
   *   - column: The column number in the generated source.  The column
   *     number is 0-based.
   *   - bias: Either 'SourceMapConsumer.GREATEST_LOWER_BOUND' or
   *     'SourceMapConsumer.LEAST_UPPER_BOUND'. Specifies whether to return the
   *     closest element that is smaller than or greater than the one we are
   *     searching for, respectively, if the exact element cannot be found.
   *     Defaults to 'SourceMapConsumer.GREATEST_LOWER_BOUND'.
   *
   * and an object is returned with the following properties:
   *
   *   - source: The original source file, or null.
   *   - line: The line number in the original source, or null.  The
   *     line number is 1-based.
   *   - column: The column number in the original source, or null.  The
   *     column number is 0-based.
   *   - name: The original identifier, or null.
   */
  BasicSourceMapConsumer.prototype.originalPositionFor =
    function SourceMapConsumer_originalPositionFor(aArgs) {
      var needle = {
        generatedLine: util.getArg(aArgs, 'line'),
        generatedColumn: util.getArg(aArgs, 'column')
      };

      var index = this._findMapping(
        needle,
        this._generatedMappings,
        "generatedLine",
        "generatedColumn",
        util.compareByGeneratedPositionsDeflated,
        util.getArg(aArgs, 'bias', SourceMapConsumer.GREATEST_LOWER_BOUND)
      );

      if (index >= 0) {
        var mapping = this._generatedMappings[index];

        if (mapping.generatedLine === needle.generatedLine) {
          var source = util.getArg(mapping, 'source', null);
          if (source !== null) {
            source = this._sources.at(source);
            source = util.computeSourceURL(this.sourceRoot, source, this._sourceMapURL);
          }
          var name = util.getArg(mapping, 'name', null);
          if (name !== null) {
            name = this._names.at(name);
          }
          return {
            source: source,
            line: util.getArg(mapping, 'originalLine', null),
            column: util.getArg(mapping, 'originalColumn', null),
            name: name
          };
        }
      }

      return {
        source: null,
        line: null,
        column: null,
        name: null
      };
    };

  /**
   * Return true if we have the source content for every source in the source
   * map, false otherwise.
   */
  BasicSourceMapConsumer.prototype.hasContentsOfAllSources =
    function BasicSourceMapConsumer_hasContentsOfAllSources() {
      if (!this.sourcesContent) {
        return false;
      }
      return this.sourcesContent.length >= this._sources.size() &&
        !this.sourcesContent.some(function (sc) { return sc == null; });
    };

  /**
   * Returns the original source content. The only argument is the url of the
   * original source file. Returns null if no original source content is
   * available.
   */
  BasicSourceMapConsumer.prototype.sourceContentFor =
    function SourceMapConsumer_sourceContentFor(aSource, nullOnMissing) {
      if (!this.sourcesContent) {
        return null;
      }

      var index = this._findSourceIndex(aSource);
      if (index >= 0) {
        return this.sourcesContent[index];
      }

      var relativeSource = aSource;
      if (this.sourceRoot != null) {
        relativeSource = util.relative(this.sourceRoot, relativeSource);
      }

      var url;
      if (this.sourceRoot != null
          && (url = util.urlParse(this.sourceRoot))) {
        // XXX: file:// URIs and absolute paths lead to unexpected behavior for
        // many users. We can help them out when they expect file:// URIs to
        // behave like it would if they were running a local HTTP server. See
        // https://bugzilla.mozilla.org/show_bug.cgi?id=885597.
        var fileUriAbsPath = relativeSource.replace(/^file:\/\//, "");
        if (url.scheme == "file"
            && this._sources.has(fileUriAbsPath)) {
          return this.sourcesContent[this._sources.indexOf(fileUriAbsPath)]
        }

        if ((!url.path || url.path == "/")
            && this._sources.has("/" + relativeSource)) {
          return this.sourcesContent[this._sources.indexOf("/" + relativeSource)];
        }
      }

      // This function is used recursively from
      // IndexedSourceMapConsumer.prototype.sourceContentFor. In that case, we
      // don't want to throw if we can't find the source - we just want to
      // return null, so we provide a flag to exit gracefully.
      if (nullOnMissing) {
        return null;
      }
      else {
        throw new Error('"' + relativeSource + '" is not in the SourceMap.');
      }
    };

  /**
   * Returns the generated line and column information for the original source,
   * line, and column positions provided. The only argument is an object with
   * the following properties:
   *
   *   - source: The filename of the original source.
   *   - line: The line number in the original source.  The line number
   *     is 1-based.
   *   - column: The column number in the original source.  The column
   *     number is 0-based.
   *   - bias: Either 'SourceMapConsumer.GREATEST_LOWER_BOUND' or
   *     'SourceMapConsumer.LEAST_UPPER_BOUND'. Specifies whether to return the
   *     closest element that is smaller than or greater than the one we are
   *     searching for, respectively, if the exact element cannot be found.
   *     Defaults to 'SourceMapConsumer.GREATEST_LOWER_BOUND'.
   *
   * and an object is returned with the following properties:
   *
   *   - line: The line number in the generated source, or null.  The
   *     line number is 1-based.
   *   - column: The column number in the generated source, or null.
   *     The column number is 0-based.
   */
  BasicSourceMapConsumer.prototype.generatedPositionFor =
    function SourceMapConsumer_generatedPositionFor(aArgs) {
      var source = util.getArg(aArgs, 'source');
      source = this._findSourceIndex(source);
      if (source < 0) {
        return {
          line: null,
          column: null,
          lastColumn: null
        };
      }

      var needle = {
        source: source,
        originalLine: util.getArg(aArgs, 'line'),
        originalColumn: util.getArg(aArgs, 'column')
      };

      var index = this._findMapping(
        needle,
        this._originalMappings,
        "originalLine",
        "originalColumn",
        util.compareByOriginalPositions,
        util.getArg(aArgs, 'bias', SourceMapConsumer.GREATEST_LOWER_BOUND)
      );

      if (index >= 0) {
        var mapping = this._originalMappings[index];

        if (mapping.source === needle.source) {
          return {
            line: util.getArg(mapping, 'generatedLine', null),
            column: util.getArg(mapping, 'generatedColumn', null),
            lastColumn: util.getArg(mapping, 'lastGeneratedColumn', null)
          };
        }
      }

      return {
        line: null,
        column: null,
        lastColumn: null
      };
    };

  var BasicSourceMapConsumer_1 = BasicSourceMapConsumer;

  /**
   * An IndexedSourceMapConsumer instance represents a parsed source map which
   * we can query for information. It differs from BasicSourceMapConsumer in
   * that it takes "indexed" source maps (i.e. ones with a "sections" field) as
   * input.
   *
   * The first parameter is a raw source map (either as a JSON string, or already
   * parsed to an object). According to the spec for indexed source maps, they
   * have the following attributes:
   *
   *   - version: Which version of the source map spec this map is following.
   *   - file: Optional. The generated file this source map is associated with.
   *   - sections: A list of section definitions.
   *
   * Each value under the "sections" field has two fields:
   *   - offset: The offset into the original specified at which this section
   *       begins to apply, defined as an object with a "line" and "column"
   *       field.
   *   - map: A source map definition. This source map could also be indexed,
   *       but doesn't have to be.
   *
   * Instead of the "map" field, it's also possible to have a "url" field
   * specifying a URL to retrieve a source map from, but that's currently
   * unsupported.
   *
   * Here's an example source map, taken from the source map spec[0], but
   * modified to omit a section which uses the "url" field.
   *
   *  {
   *    version : 3,
   *    file: "app.js",
   *    sections: [{
   *      offset: {line:100, column:10},
   *      map: {
   *        version : 3,
   *        file: "section.js",
   *        sources: ["foo.js", "bar.js"],
   *        names: ["src", "maps", "are", "fun"],
   *        mappings: "AAAA,E;;ABCDE;"
   *      }
   *    }],
   *  }
   *
   * The second parameter, if given, is a string whose value is the URL
   * at which the source map was found.  This URL is used to compute the
   * sources array.
   *
   * [0]: https://docs.google.com/document/d/1U1RGAehQwRypUTovF1KRlpiOFze0b-_2gc6fAH0KY0k/edit#heading=h.535es3xeprgt
   */
  function IndexedSourceMapConsumer(aSourceMap, aSourceMapURL) {
    var sourceMap = aSourceMap;
    if (typeof aSourceMap === 'string') {
      sourceMap = util.parseSourceMapInput(aSourceMap);
    }

    var version = util.getArg(sourceMap, 'version');
    var sections = util.getArg(sourceMap, 'sections');

    if (version != this._version) {
      throw new Error('Unsupported version: ' + version);
    }

    this._sources = new ArraySet$2();
    this._names = new ArraySet$2();

    var lastOffset = {
      line: -1,
      column: 0
    };
    this._sections = sections.map(function (s) {
      if (s.url) {
        // The url field will require support for asynchronicity.
        // See https://github.com/mozilla/source-map/issues/16
        throw new Error('Support for url field in sections not implemented.');
      }
      var offset = util.getArg(s, 'offset');
      var offsetLine = util.getArg(offset, 'line');
      var offsetColumn = util.getArg(offset, 'column');

      if (offsetLine < lastOffset.line ||
          (offsetLine === lastOffset.line && offsetColumn < lastOffset.column)) {
        throw new Error('Section offsets must be ordered and non-overlapping.');
      }
      lastOffset = offset;

      return {
        generatedOffset: {
          // The offset fields are 0-based, but we use 1-based indices when
          // encoding/decoding from VLQ.
          generatedLine: offsetLine + 1,
          generatedColumn: offsetColumn + 1
        },
        consumer: new SourceMapConsumer(util.getArg(s, 'map'), aSourceMapURL)
      }
    });
  }

  IndexedSourceMapConsumer.prototype = Object.create(SourceMapConsumer.prototype);
  IndexedSourceMapConsumer.prototype.constructor = SourceMapConsumer;

  /**
   * The version of the source mapping spec that we are consuming.
   */
  IndexedSourceMapConsumer.prototype._version = 3;

  /**
   * The list of original sources.
   */
  Object.defineProperty(IndexedSourceMapConsumer.prototype, 'sources', {
    get: function () {
      var sources = [];
      for (var i = 0; i < this._sections.length; i++) {
        for (var j = 0; j < this._sections[i].consumer.sources.length; j++) {
          sources.push(this._sections[i].consumer.sources[j]);
        }
      }
      return sources;
    }
  });

  /**
   * Returns the original source, line, and column information for the generated
   * source's line and column positions provided. The only argument is an object
   * with the following properties:
   *
   *   - line: The line number in the generated source.  The line number
   *     is 1-based.
   *   - column: The column number in the generated source.  The column
   *     number is 0-based.
   *
   * and an object is returned with the following properties:
   *
   *   - source: The original source file, or null.
   *   - line: The line number in the original source, or null.  The
   *     line number is 1-based.
   *   - column: The column number in the original source, or null.  The
   *     column number is 0-based.
   *   - name: The original identifier, or null.
   */
  IndexedSourceMapConsumer.prototype.originalPositionFor =
    function IndexedSourceMapConsumer_originalPositionFor(aArgs) {
      var needle = {
        generatedLine: util.getArg(aArgs, 'line'),
        generatedColumn: util.getArg(aArgs, 'column')
      };

      // Find the section containing the generated position we're trying to map
      // to an original position.
      var sectionIndex = binarySearch.search(needle, this._sections,
        function(needle, section) {
          var cmp = needle.generatedLine - section.generatedOffset.generatedLine;
          if (cmp) {
            return cmp;
          }

          return (needle.generatedColumn -
                  section.generatedOffset.generatedColumn);
        });
      var section = this._sections[sectionIndex];

      if (!section) {
        return {
          source: null,
          line: null,
          column: null,
          name: null
        };
      }

      return section.consumer.originalPositionFor({
        line: needle.generatedLine -
          (section.generatedOffset.generatedLine - 1),
        column: needle.generatedColumn -
          (section.generatedOffset.generatedLine === needle.generatedLine
           ? section.generatedOffset.generatedColumn - 1
           : 0),
        bias: aArgs.bias
      });
    };

  /**
   * Return true if we have the source content for every source in the source
   * map, false otherwise.
   */
  IndexedSourceMapConsumer.prototype.hasContentsOfAllSources =
    function IndexedSourceMapConsumer_hasContentsOfAllSources() {
      return this._sections.every(function (s) {
        return s.consumer.hasContentsOfAllSources();
      });
    };

  /**
   * Returns the original source content. The only argument is the url of the
   * original source file. Returns null if no original source content is
   * available.
   */
  IndexedSourceMapConsumer.prototype.sourceContentFor =
    function IndexedSourceMapConsumer_sourceContentFor(aSource, nullOnMissing) {
      for (var i = 0; i < this._sections.length; i++) {
        var section = this._sections[i];

        var content = section.consumer.sourceContentFor(aSource, true);
        if (content) {
          return content;
        }
      }
      if (nullOnMissing) {
        return null;
      }
      else {
        throw new Error('"' + aSource + '" is not in the SourceMap.');
      }
    };

  /**
   * Returns the generated line and column information for the original source,
   * line, and column positions provided. The only argument is an object with
   * the following properties:
   *
   *   - source: The filename of the original source.
   *   - line: The line number in the original source.  The line number
   *     is 1-based.
   *   - column: The column number in the original source.  The column
   *     number is 0-based.
   *
   * and an object is returned with the following properties:
   *
   *   - line: The line number in the generated source, or null.  The
   *     line number is 1-based. 
   *   - column: The column number in the generated source, or null.
   *     The column number is 0-based.
   */
  IndexedSourceMapConsumer.prototype.generatedPositionFor =
    function IndexedSourceMapConsumer_generatedPositionFor(aArgs) {
      for (var i = 0; i < this._sections.length; i++) {
        var section = this._sections[i];

        // Only consider this section if the requested source is in the list of
        // sources of the consumer.
        if (section.consumer._findSourceIndex(util.getArg(aArgs, 'source')) === -1) {
          continue;
        }
        var generatedPosition = section.consumer.generatedPositionFor(aArgs);
        if (generatedPosition) {
          var ret = {
            line: generatedPosition.line +
              (section.generatedOffset.generatedLine - 1),
            column: generatedPosition.column +
              (section.generatedOffset.generatedLine === generatedPosition.line
               ? section.generatedOffset.generatedColumn - 1
               : 0)
          };
          return ret;
        }
      }

      return {
        line: null,
        column: null
      };
    };

  /**
   * Parse the mappings in a string in to a data structure which we can easily
   * query (the ordered arrays in the `this.__generatedMappings` and
   * `this.__originalMappings` properties).
   */
  IndexedSourceMapConsumer.prototype._parseMappings =
    function IndexedSourceMapConsumer_parseMappings(aStr, aSourceRoot) {
      this.__generatedMappings = [];
      this.__originalMappings = [];
      for (var i = 0; i < this._sections.length; i++) {
        var section = this._sections[i];
        var sectionMappings = section.consumer._generatedMappings;
        for (var j = 0; j < sectionMappings.length; j++) {
          var mapping = sectionMappings[j];

          var source = section.consumer._sources.at(mapping.source);
          source = util.computeSourceURL(section.consumer.sourceRoot, source, this._sourceMapURL);
          this._sources.add(source);
          source = this._sources.indexOf(source);

          var name = null;
          if (mapping.name) {
            name = section.consumer._names.at(mapping.name);
            this._names.add(name);
            name = this._names.indexOf(name);
          }

          // The mappings coming from the consumer for the section have
          // generated positions relative to the start of the section, so we
          // need to offset them to be relative to the start of the concatenated
          // generated file.
          var adjustedMapping = {
            source: source,
            generatedLine: mapping.generatedLine +
              (section.generatedOffset.generatedLine - 1),
            generatedColumn: mapping.generatedColumn +
              (section.generatedOffset.generatedLine === mapping.generatedLine
              ? section.generatedOffset.generatedColumn - 1
              : 0),
            originalLine: mapping.originalLine,
            originalColumn: mapping.originalColumn,
            name: name
          };

          this.__generatedMappings.push(adjustedMapping);
          if (typeof adjustedMapping.originalLine === 'number') {
            this.__originalMappings.push(adjustedMapping);
          }
        }
      }

      quickSort$1(this.__generatedMappings, util.compareByGeneratedPositionsDeflated);
      quickSort$1(this.__originalMappings, util.compareByOriginalPositions);
    };

  var IndexedSourceMapConsumer_1 = IndexedSourceMapConsumer;

  var sourceMapConsumer = {
  	SourceMapConsumer: SourceMapConsumer_1,
  	BasicSourceMapConsumer: BasicSourceMapConsumer_1,
  	IndexedSourceMapConsumer: IndexedSourceMapConsumer_1
  };

  /* -*- Mode: js; js-indent-level: 2; -*- */
  /*
   * Copyright 2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE or:
   * http://opensource.org/licenses/BSD-3-Clause
   */

  var SourceMapGenerator$1 = sourceMapGenerator.SourceMapGenerator;


  // Matches a Windows-style `\r\n` newline or a `\n` newline used by all other
  // operating systems these days (capturing the result).
  var REGEX_NEWLINE = /(\r?\n)/;

  // Newline character code for charCodeAt() comparisons
  var NEWLINE_CODE = 10;

  // Private symbol for identifying `SourceNode`s when multiple versions of
  // the source-map library are loaded. This MUST NOT CHANGE across
  // versions!
  var isSourceNode = "$$$isSourceNode$$$";

  /**
   * SourceNodes provide a way to abstract over interpolating/concatenating
   * snippets of generated JavaScript source code while maintaining the line and
   * column information associated with the original source code.
   *
   * @param aLine The original line number.
   * @param aColumn The original column number.
   * @param aSource The original source's filename.
   * @param aChunks Optional. An array of strings which are snippets of
   *        generated JS, or other SourceNodes.
   * @param aName The original identifier.
   */
  function SourceNode(aLine, aColumn, aSource, aChunks, aName) {
    this.children = [];
    this.sourceContents = {};
    this.line = aLine == null ? null : aLine;
    this.column = aColumn == null ? null : aColumn;
    this.source = aSource == null ? null : aSource;
    this.name = aName == null ? null : aName;
    this[isSourceNode] = true;
    if (aChunks != null) this.add(aChunks);
  }

  /**
   * Creates a SourceNode from generated code and a SourceMapConsumer.
   *
   * @param aGeneratedCode The generated code
   * @param aSourceMapConsumer The SourceMap for the generated code
   * @param aRelativePath Optional. The path that relative sources in the
   *        SourceMapConsumer should be relative to.
   */
  SourceNode.fromStringWithSourceMap =
    function SourceNode_fromStringWithSourceMap(aGeneratedCode, aSourceMapConsumer, aRelativePath) {
      // The SourceNode we want to fill with the generated code
      // and the SourceMap
      var node = new SourceNode();

      // All even indices of this array are one line of the generated code,
      // while all odd indices are the newlines between two adjacent lines
      // (since `REGEX_NEWLINE` captures its match).
      // Processed fragments are accessed by calling `shiftNextLine`.
      var remainingLines = aGeneratedCode.split(REGEX_NEWLINE);
      var remainingLinesIndex = 0;
      var shiftNextLine = function() {
        var lineContents = getNextLine();
        // The last line of a file might not have a newline.
        var newLine = getNextLine() || "";
        return lineContents + newLine;

        function getNextLine() {
          return remainingLinesIndex < remainingLines.length ?
              remainingLines[remainingLinesIndex++] : undefined;
        }
      };

      // We need to remember the position of "remainingLines"
      var lastGeneratedLine = 1, lastGeneratedColumn = 0;

      // The generate SourceNodes we need a code range.
      // To extract it current and last mapping is used.
      // Here we store the last mapping.
      var lastMapping = null;

      aSourceMapConsumer.eachMapping(function (mapping) {
        if (lastMapping !== null) {
          // We add the code from "lastMapping" to "mapping":
          // First check if there is a new line in between.
          if (lastGeneratedLine < mapping.generatedLine) {
            // Associate first line with "lastMapping"
            addMappingWithCode(lastMapping, shiftNextLine());
            lastGeneratedLine++;
            lastGeneratedColumn = 0;
            // The remaining code is added without mapping
          } else {
            // There is no new line in between.
            // Associate the code between "lastGeneratedColumn" and
            // "mapping.generatedColumn" with "lastMapping"
            var nextLine = remainingLines[remainingLinesIndex] || '';
            var code = nextLine.substr(0, mapping.generatedColumn -
                                          lastGeneratedColumn);
            remainingLines[remainingLinesIndex] = nextLine.substr(mapping.generatedColumn -
                                                lastGeneratedColumn);
            lastGeneratedColumn = mapping.generatedColumn;
            addMappingWithCode(lastMapping, code);
            // No more remaining code, continue
            lastMapping = mapping;
            return;
          }
        }
        // We add the generated code until the first mapping
        // to the SourceNode without any mapping.
        // Each line is added as separate string.
        while (lastGeneratedLine < mapping.generatedLine) {
          node.add(shiftNextLine());
          lastGeneratedLine++;
        }
        if (lastGeneratedColumn < mapping.generatedColumn) {
          var nextLine = remainingLines[remainingLinesIndex] || '';
          node.add(nextLine.substr(0, mapping.generatedColumn));
          remainingLines[remainingLinesIndex] = nextLine.substr(mapping.generatedColumn);
          lastGeneratedColumn = mapping.generatedColumn;
        }
        lastMapping = mapping;
      }, this);
      // We have processed all mappings.
      if (remainingLinesIndex < remainingLines.length) {
        if (lastMapping) {
          // Associate the remaining code in the current line with "lastMapping"
          addMappingWithCode(lastMapping, shiftNextLine());
        }
        // and add the remaining lines without any mapping
        node.add(remainingLines.splice(remainingLinesIndex).join(""));
      }

      // Copy sourcesContent into SourceNode
      aSourceMapConsumer.sources.forEach(function (sourceFile) {
        var content = aSourceMapConsumer.sourceContentFor(sourceFile);
        if (content != null) {
          if (aRelativePath != null) {
            sourceFile = util.join(aRelativePath, sourceFile);
          }
          node.setSourceContent(sourceFile, content);
        }
      });

      return node;

      function addMappingWithCode(mapping, code) {
        if (mapping === null || mapping.source === undefined) {
          node.add(code);
        } else {
          var source = aRelativePath
            ? util.join(aRelativePath, mapping.source)
            : mapping.source;
          node.add(new SourceNode(mapping.originalLine,
                                  mapping.originalColumn,
                                  source,
                                  code,
                                  mapping.name));
        }
      }
    };

  /**
   * Add a chunk of generated JS to this source node.
   *
   * @param aChunk A string snippet of generated JS code, another instance of
   *        SourceNode, or an array where each member is one of those things.
   */
  SourceNode.prototype.add = function SourceNode_add(aChunk) {
    if (Array.isArray(aChunk)) {
      aChunk.forEach(function (chunk) {
        this.add(chunk);
      }, this);
    }
    else if (aChunk[isSourceNode] || typeof aChunk === "string") {
      if (aChunk) {
        this.children.push(aChunk);
      }
    }
    else {
      throw new TypeError(
        "Expected a SourceNode, string, or an array of SourceNodes and strings. Got " + aChunk
      );
    }
    return this;
  };

  /**
   * Add a chunk of generated JS to the beginning of this source node.
   *
   * @param aChunk A string snippet of generated JS code, another instance of
   *        SourceNode, or an array where each member is one of those things.
   */
  SourceNode.prototype.prepend = function SourceNode_prepend(aChunk) {
    if (Array.isArray(aChunk)) {
      for (var i = aChunk.length-1; i >= 0; i--) {
        this.prepend(aChunk[i]);
      }
    }
    else if (aChunk[isSourceNode] || typeof aChunk === "string") {
      this.children.unshift(aChunk);
    }
    else {
      throw new TypeError(
        "Expected a SourceNode, string, or an array of SourceNodes and strings. Got " + aChunk
      );
    }
    return this;
  };

  /**
   * Walk over the tree of JS snippets in this node and its children. The
   * walking function is called once for each snippet of JS and is passed that
   * snippet and the its original associated source's line/column location.
   *
   * @param aFn The traversal function.
   */
  SourceNode.prototype.walk = function SourceNode_walk(aFn) {
    var chunk;
    for (var i = 0, len = this.children.length; i < len; i++) {
      chunk = this.children[i];
      if (chunk[isSourceNode]) {
        chunk.walk(aFn);
      }
      else {
        if (chunk !== '') {
          aFn(chunk, { source: this.source,
                       line: this.line,
                       column: this.column,
                       name: this.name });
        }
      }
    }
  };

  /**
   * Like `String.prototype.join` except for SourceNodes. Inserts `aStr` between
   * each of `this.children`.
   *
   * @param aSep The separator.
   */
  SourceNode.prototype.join = function SourceNode_join(aSep) {
    var newChildren;
    var i;
    var len = this.children.length;
    if (len > 0) {
      newChildren = [];
      for (i = 0; i < len-1; i++) {
        newChildren.push(this.children[i]);
        newChildren.push(aSep);
      }
      newChildren.push(this.children[i]);
      this.children = newChildren;
    }
    return this;
  };

  /**
   * Call String.prototype.replace on the very right-most source snippet. Useful
   * for trimming whitespace from the end of a source node, etc.
   *
   * @param aPattern The pattern to replace.
   * @param aReplacement The thing to replace the pattern with.
   */
  SourceNode.prototype.replaceRight = function SourceNode_replaceRight(aPattern, aReplacement) {
    var lastChild = this.children[this.children.length - 1];
    if (lastChild[isSourceNode]) {
      lastChild.replaceRight(aPattern, aReplacement);
    }
    else if (typeof lastChild === 'string') {
      this.children[this.children.length - 1] = lastChild.replace(aPattern, aReplacement);
    }
    else {
      this.children.push(''.replace(aPattern, aReplacement));
    }
    return this;
  };

  /**
   * Set the source content for a source file. This will be added to the SourceMapGenerator
   * in the sourcesContent field.
   *
   * @param aSourceFile The filename of the source file
   * @param aSourceContent The content of the source file
   */
  SourceNode.prototype.setSourceContent =
    function SourceNode_setSourceContent(aSourceFile, aSourceContent) {
      this.sourceContents[util.toSetString(aSourceFile)] = aSourceContent;
    };

  /**
   * Walk over the tree of SourceNodes. The walking function is called for each
   * source file content and is passed the filename and source content.
   *
   * @param aFn The traversal function.
   */
  SourceNode.prototype.walkSourceContents =
    function SourceNode_walkSourceContents(aFn) {
      for (var i = 0, len = this.children.length; i < len; i++) {
        if (this.children[i][isSourceNode]) {
          this.children[i].walkSourceContents(aFn);
        }
      }

      var sources = Object.keys(this.sourceContents);
      for (var i = 0, len = sources.length; i < len; i++) {
        aFn(util.fromSetString(sources[i]), this.sourceContents[sources[i]]);
      }
    };

  /**
   * Return the string representation of this source node. Walks over the tree
   * and concatenates all the various snippets together to one string.
   */
  SourceNode.prototype.toString = function SourceNode_toString() {
    var str = "";
    this.walk(function (chunk) {
      str += chunk;
    });
    return str;
  };

  /**
   * Returns the string representation of this source node along with a source
   * map.
   */
  SourceNode.prototype.toStringWithSourceMap = function SourceNode_toStringWithSourceMap(aArgs) {
    var generated = {
      code: "",
      line: 1,
      column: 0
    };
    var map = new SourceMapGenerator$1(aArgs);
    var sourceMappingActive = false;
    var lastOriginalSource = null;
    var lastOriginalLine = null;
    var lastOriginalColumn = null;
    var lastOriginalName = null;
    this.walk(function (chunk, original) {
      generated.code += chunk;
      if (original.source !== null
          && original.line !== null
          && original.column !== null) {
        if(lastOriginalSource !== original.source
           || lastOriginalLine !== original.line
           || lastOriginalColumn !== original.column
           || lastOriginalName !== original.name) {
          map.addMapping({
            source: original.source,
            original: {
              line: original.line,
              column: original.column
            },
            generated: {
              line: generated.line,
              column: generated.column
            },
            name: original.name
          });
        }
        lastOriginalSource = original.source;
        lastOriginalLine = original.line;
        lastOriginalColumn = original.column;
        lastOriginalName = original.name;
        sourceMappingActive = true;
      } else if (sourceMappingActive) {
        map.addMapping({
          generated: {
            line: generated.line,
            column: generated.column
          }
        });
        lastOriginalSource = null;
        sourceMappingActive = false;
      }
      for (var idx = 0, length = chunk.length; idx < length; idx++) {
        if (chunk.charCodeAt(idx) === NEWLINE_CODE) {
          generated.line++;
          generated.column = 0;
          // Mappings end at eol
          if (idx + 1 === length) {
            lastOriginalSource = null;
            sourceMappingActive = false;
          } else if (sourceMappingActive) {
            map.addMapping({
              source: original.source,
              original: {
                line: original.line,
                column: original.column
              },
              generated: {
                line: generated.line,
                column: generated.column
              },
              name: original.name
            });
          }
        } else {
          generated.column++;
        }
      }
    });
    this.walkSourceContents(function (sourceFile, sourceContent) {
      map.setSourceContent(sourceFile, sourceContent);
    });

    return { code: generated.code, map: map };
  };

  var SourceNode_1 = SourceNode;

  var sourceNode = {
  	SourceNode: SourceNode_1
  };

  /*
   * Copyright 2009-2011 Mozilla Foundation and contributors
   * Licensed under the New BSD license. See LICENSE.txt or:
   * http://opensource.org/licenses/BSD-3-Clause
   */
  var SourceMapGenerator$2 = sourceMapGenerator.SourceMapGenerator;
  var SourceMapConsumer$1 = sourceMapConsumer.SourceMapConsumer;
  var SourceNode$1 = sourceNode.SourceNode;

  var sourceMap = {
  	SourceMapGenerator: SourceMapGenerator$2,
  	SourceMapConsumer: SourceMapConsumer$1,
  	SourceNode: SourceNode$1
  };

  var previousMap = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _sourceMap = _interopRequireDefault(sourceMap);

  var _path = _interopRequireDefault(path__default['default']);

  var _fs = _interopRequireDefault(fs__default['default']);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function fromBase64(str) {
    if (Buffer) {
      return Buffer.from(str, 'base64').toString();
    } else {
      return window.atob(str);
    }
  }
  /**
   * Source map information from input CSS.
   * For example, source map after Sass compiler.
   *
   * This class will automatically find source map in input CSS or in file system
   * near input file (according `from` option).
   *
   * @example
   * const root = postcss.parse(css, { from: 'a.sass.css' })
   * root.input.map //=> PreviousMap
   */


  var PreviousMap =
  /*#__PURE__*/
  function () {
    /**
     * @param {string}         css    Input CSS source.
     * @param {processOptions} [opts] {@link Processor#process} options.
     */
    function PreviousMap(css, opts) {
      this.loadAnnotation(css);
      /**
       * Was source map inlined by data-uri to input CSS.
       *
       * @type {boolean}
       */

      this.inline = this.startWith(this.annotation, 'data:');
      var prev = opts.map ? opts.map.prev : undefined;
      var text = this.loadMap(opts.from, prev);
      if (text) this.text = text;
    }
    /**
     * Create a instance of `SourceMapGenerator` class
     * from the `source-map` library to work with source map information.
     *
     * It is lazy method, so it will create object only on first call
     * and then it will use cache.
     *
     * @return {SourceMapGenerator} Object with source map information.
     */


    var _proto = PreviousMap.prototype;

    _proto.consumer = function consumer() {
      if (!this.consumerCache) {
        this.consumerCache = new _sourceMap.default.SourceMapConsumer(this.text);
      }

      return this.consumerCache;
    }
    /**
     * Does source map contains `sourcesContent` with input source text.
     *
     * @return {boolean} Is `sourcesContent` present.
     */
    ;

    _proto.withContent = function withContent() {
      return !!(this.consumer().sourcesContent && this.consumer().sourcesContent.length > 0);
    };

    _proto.startWith = function startWith(string, start) {
      if (!string) return false;
      return string.substr(0, start.length) === start;
    };

    _proto.getAnnotationURL = function getAnnotationURL(sourceMapString) {
      return sourceMapString.match(/\/\*\s*# sourceMappingURL=(.*)\s*\*\//)[1].trim();
    };

    _proto.loadAnnotation = function loadAnnotation(css) {
      var annotations = css.match(/\/\*\s*# sourceMappingURL=(.*)\s*\*\//mg);

      if (annotations && annotations.length > 0) {
        // Locate the last sourceMappingURL to avoid picking up
        // sourceMappingURLs from comments, strings, etc.
        var lastAnnotation = annotations[annotations.length - 1];

        if (lastAnnotation) {
          this.annotation = this.getAnnotationURL(lastAnnotation);
        }
      }
    };

    _proto.decodeInline = function decodeInline(text) {
      var baseCharsetUri = /^data:application\/json;charset=utf-?8;base64,/;
      var baseUri = /^data:application\/json;base64,/;
      var uri = 'data:application/json,';

      if (this.startWith(text, uri)) {
        return decodeURIComponent(text.substr(uri.length));
      }

      if (baseCharsetUri.test(text) || baseUri.test(text)) {
        return fromBase64(text.substr(RegExp.lastMatch.length));
      }

      var encoding = text.match(/data:application\/json;([^,]+),/)[1];
      throw new Error('Unsupported source map encoding ' + encoding);
    };

    _proto.loadMap = function loadMap(file, prev) {
      if (prev === false) return false;

      if (prev) {
        if (typeof prev === 'string') {
          return prev;
        } else if (typeof prev === 'function') {
          var prevPath = prev(file);

          if (prevPath && _fs.default.existsSync && _fs.default.existsSync(prevPath)) {
            return _fs.default.readFileSync(prevPath, 'utf-8').toString().trim();
          } else {
            throw new Error('Unable to load previous source map: ' + prevPath.toString());
          }
        } else if (prev instanceof _sourceMap.default.SourceMapConsumer) {
          return _sourceMap.default.SourceMapGenerator.fromSourceMap(prev).toString();
        } else if (prev instanceof _sourceMap.default.SourceMapGenerator) {
          return prev.toString();
        } else if (this.isMap(prev)) {
          return JSON.stringify(prev);
        } else {
          throw new Error('Unsupported previous source map format: ' + prev.toString());
        }
      } else if (this.inline) {
        return this.decodeInline(this.annotation);
      } else if (this.annotation) {
        var map = this.annotation;
        if (file) map = _path.default.join(_path.default.dirname(file), map);
        this.root = _path.default.dirname(map);

        if (_fs.default.existsSync && _fs.default.existsSync(map)) {
          return _fs.default.readFileSync(map, 'utf-8').toString().trim();
        } else {
          return false;
        }
      }
    };

    _proto.isMap = function isMap(map) {
      if (typeof map !== 'object') return false;
      return typeof map.mappings === 'string' || typeof map._mappings === 'string';
    };

    return PreviousMap;
  }();

  var _default = PreviousMap;
  exports.default = _default;
  module.exports = exports.default;

  });

  var input = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _path = _interopRequireDefault(path__default['default']);

  var _cssSyntaxError = _interopRequireDefault(cssSyntaxError);

  var _previousMap = _interopRequireDefault(previousMap);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

  function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

  var sequence = 0;
  /**
   * Represents the source CSS.
   *
   * @example
   * const root  = postcss.parse(css, { from: file })
   * const input = root.source.input
   */

  var Input =
  /*#__PURE__*/
  function () {
    /**
     * @param {string} css    Input CSS source.
     * @param {object} [opts] {@link Processor#process} options.
     */
    function Input(css, opts) {
      if (opts === void 0) {
        opts = {};
      }

      if (css === null || typeof css === 'undefined' || typeof css === 'object' && !css.toString) {
        throw new Error("PostCSS received " + css + " instead of CSS string");
      }
      /**
       * Input CSS source
       *
       * @type {string}
       *
       * @example
       * const input = postcss.parse('a{}', { from: file }).input
       * input.css //=> "a{}"
       */


      this.css = css.toString();

      if (this.css[0] === "\uFEFF" || this.css[0] === "\uFFFE") {
        this.hasBOM = true;
        this.css = this.css.slice(1);
      } else {
        this.hasBOM = false;
      }

      if (opts.from) {
        if (/^\w+:\/\//.test(opts.from) || _path.default.isAbsolute(opts.from)) {
          /**
           * The absolute path to the CSS source file defined
           * with the `from` option.
           *
           * @type {string}
           *
           * @example
           * const root = postcss.parse(css, { from: 'a.css' })
           * root.source.input.file //=> '/home/ai/a.css'
           */
          this.file = opts.from;
        } else {
          this.file = _path.default.resolve(opts.from);
        }
      }

      var map = new _previousMap.default(this.css, opts);

      if (map.text) {
        /**
         * The input source map passed from a compilation step before PostCSS
         * (for example, from Sass compiler).
         *
         * @type {PreviousMap}
         *
         * @example
         * root.source.input.map.consumer().sources //=> ['a.sass']
         */
        this.map = map;
        var file = map.consumer().file;
        if (!this.file && file) this.file = this.mapResolve(file);
      }

      if (!this.file) {
        sequence += 1;
        /**
         * The unique ID of the CSS source. It will be created if `from` option
         * is not provided (because PostCSS does not know the file path).
         *
         * @type {string}
         *
         * @example
         * const root = postcss.parse(css)
         * root.source.input.file //=> undefined
         * root.source.input.id   //=> "<input css 1>"
         */

        this.id = '<input css ' + sequence + '>';
      }

      if (this.map) this.map.file = this.from;
    }

    var _proto = Input.prototype;

    _proto.error = function error(message, line, column, opts) {
      if (opts === void 0) {
        opts = {};
      }

      var result;
      var origin = this.origin(line, column);

      if (origin) {
        result = new _cssSyntaxError.default(message, origin.line, origin.column, origin.source, origin.file, opts.plugin);
      } else {
        result = new _cssSyntaxError.default(message, line, column, this.css, this.file, opts.plugin);
      }

      result.input = {
        line: line,
        column: column,
        source: this.css
      };
      if (this.file) result.input.file = this.file;
      return result;
    }
    /**
     * Reads the input source map and returns a symbol position
     * in the input source (e.g., in a Sass file that was compiled
     * to CSS before being passed to PostCSS).
     *
     * @param {number} line   Line in input CSS.
     * @param {number} column Column in input CSS.
     *
     * @return {filePosition} Position in input source.
     *
     * @example
     * root.source.input.origin(1, 1) //=> { file: 'a.css', line: 3, column: 1 }
     */
    ;

    _proto.origin = function origin(line, column) {
      if (!this.map) return false;
      var consumer = this.map.consumer();
      var from = consumer.originalPositionFor({
        line: line,
        column: column
      });
      if (!from.source) return false;
      var result = {
        file: this.mapResolve(from.source),
        line: from.line,
        column: from.column
      };
      var source = consumer.sourceContentFor(from.source);
      if (source) result.source = source;
      return result;
    };

    _proto.mapResolve = function mapResolve(file) {
      if (/^\w+:\/\//.test(file)) {
        return file;
      }

      return _path.default.resolve(this.map.consumer().sourceRoot || '.', file);
    }
    /**
     * The CSS source identifier. Contains {@link Input#file} if the user
     * set the `from` option, or {@link Input#id} if they did not.
     *
     * @type {string}
     *
     * @example
     * const root = postcss.parse(css, { from: 'a.css' })
     * root.source.input.from //=> "/home/ai/a.css"
     *
     * const root = postcss.parse(css)
     * root.source.input.from //=> "<input css 1>"
     */
    ;

    _createClass(Input, [{
      key: "from",
      get: function get() {
        return this.file || this.id;
      }
    }]);

    return Input;
  }();

  var _default = Input;
  /**
   * @typedef  {object} filePosition
   * @property {string} file   Path to file.
   * @property {number} line   Source line in file.
   * @property {number} column Source column in file.
   */

  exports.default = _default;
  module.exports = exports.default;

  });

  var terminalHighlight_1 = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _chalk = _interopRequireDefault(chalk);

  var _tokenize = _interopRequireDefault(tokenize);

  var _input = _interopRequireDefault(input);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  var HIGHLIGHT_THEME = {
    'brackets': _chalk.default.cyan,
    'at-word': _chalk.default.cyan,
    'comment': _chalk.default.gray,
    'string': _chalk.default.green,
    'class': _chalk.default.yellow,
    'call': _chalk.default.cyan,
    'hash': _chalk.default.magenta,
    '(': _chalk.default.cyan,
    ')': _chalk.default.cyan,
    '{': _chalk.default.yellow,
    '}': _chalk.default.yellow,
    '[': _chalk.default.yellow,
    ']': _chalk.default.yellow,
    ':': _chalk.default.yellow,
    ';': _chalk.default.yellow
  };

  function getTokenType(_ref, processor) {
    var type = _ref[0],
        value = _ref[1];

    if (type === 'word') {
      if (value[0] === '.') {
        return 'class';
      }

      if (value[0] === '#') {
        return 'hash';
      }
    }

    if (!processor.endOfFile()) {
      var next = processor.nextToken();
      processor.back(next);
      if (next[0] === 'brackets' || next[0] === '(') return 'call';
    }

    return type;
  }

  function terminalHighlight(css) {
    var processor = (0, _tokenize.default)(new _input.default(css), {
      ignoreErrors: true
    });
    var result = '';

    var _loop = function _loop() {
      var token = processor.nextToken();
      var color = HIGHLIGHT_THEME[getTokenType(token, processor)];

      if (color) {
        result += token[1].split(/\r?\n/).map(function (i) {
          return color(i);
        }).join('\n');
      } else {
        result += token[1];
      }
    };

    while (!processor.endOfFile()) {
      _loop();
    }

    return result;
  }

  var _default = terminalHighlight;
  exports.default = _default;
  module.exports = exports.default;

  });

  var cssSyntaxError = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _supportsColor = _interopRequireDefault(supportsColor_1);

  var _chalk = _interopRequireDefault(chalk);

  var _terminalHighlight = _interopRequireDefault(terminalHighlight_1);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }

  function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

  function _wrapNativeSuper(Class) { var _cache = typeof Map === "function" ? new Map() : undefined; _wrapNativeSuper = function _wrapNativeSuper(Class) { if (Class === null || !_isNativeFunction(Class)) return Class; if (typeof Class !== "function") { throw new TypeError("Super expression must either be null or a function"); } if (typeof _cache !== "undefined") { if (_cache.has(Class)) return _cache.get(Class); _cache.set(Class, Wrapper); } function Wrapper() { return _construct(Class, arguments, _getPrototypeOf(this).constructor); } Wrapper.prototype = Object.create(Class.prototype, { constructor: { value: Wrapper, enumerable: false, writable: true, configurable: true } }); return _setPrototypeOf(Wrapper, Class); }; return _wrapNativeSuper(Class); }

  function isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }

  function _construct(Parent, args, Class) { if (isNativeReflectConstruct()) { _construct = Reflect.construct; } else { _construct = function _construct(Parent, args, Class) { var a = [null]; a.push.apply(a, args); var Constructor = Function.bind.apply(Parent, a); var instance = new Constructor(); if (Class) _setPrototypeOf(instance, Class.prototype); return instance; }; } return _construct.apply(null, arguments); }

  function _isNativeFunction(fn) { return Function.toString.call(fn).indexOf("[native code]") !== -1; }

  function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }

  function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }

  /**
   * The CSS parser throws this error for broken CSS.
   *
   * Custom parsers can throw this error for broken custom syntax using
   * the {@link Node#error} method.
   *
   * PostCSS will use the input source map to detect the original error location.
   * If you wrote a Sass file, compiled it to CSS and then parsed it with PostCSS,
   * PostCSS will show the original position in the Sass file.
   *
   * If you need the position in the PostCSS input
   * (e.g., to debug the previous compiler), use `error.input.file`.
   *
   * @example
   * // Catching and checking syntax error
   * try {
   *   postcss.parse('a{')
   * } catch (error) {
   *   if (error.name === 'CssSyntaxError') {
   *     error //=> CssSyntaxError
   *   }
   * }
   *
   * @example
   * // Raising error from plugin
   * throw node.error('Unknown variable', { plugin: 'postcss-vars' })
   */
  var CssSyntaxError =
  /*#__PURE__*/
  function (_Error) {
    _inheritsLoose(CssSyntaxError, _Error);

    /**
     * @param {string} message  Error message.
     * @param {number} [line]   Source line of the error.
     * @param {number} [column] Source column of the error.
     * @param {string} [source] Source code of the broken file.
     * @param {string} [file]   Absolute path to the broken file.
     * @param {string} [plugin] PostCSS plugin name, if error came from plugin.
     */
    function CssSyntaxError(message, line, column, source, file, plugin) {
      var _this;

      _this = _Error.call(this, message) || this;
      /**
       * Always equal to `'CssSyntaxError'`. You should always check error type
       * by `error.name === 'CssSyntaxError'`
       * instead of `error instanceof CssSyntaxError`,
       * because npm could have several PostCSS versions.
       *
       * @type {string}
       *
       * @example
       * if (error.name === 'CssSyntaxError') {
       *   error //=> CssSyntaxError
       * }
       */

      _this.name = 'CssSyntaxError';
      /**
       * Error message.
       *
       * @type {string}
       *
       * @example
       * error.message //=> 'Unclosed block'
       */

      _this.reason = message;

      if (file) {
        /**
         * Absolute path to the broken file.
         *
         * @type {string}
         *
         * @example
         * error.file       //=> 'a.sass'
         * error.input.file //=> 'a.css'
         */
        _this.file = file;
      }

      if (source) {
        /**
         * Source code of the broken file.
         *
         * @type {string}
         *
         * @example
         * error.source       //=> 'a { b {} }'
         * error.input.column //=> 'a b { }'
         */
        _this.source = source;
      }

      if (plugin) {
        /**
         * Plugin name, if error came from plugin.
         *
         * @type {string}
         *
         * @example
         * error.plugin //=> 'postcss-vars'
         */
        _this.plugin = plugin;
      }

      if (typeof line !== 'undefined' && typeof column !== 'undefined') {
        /**
         * Source line of the error.
         *
         * @type {number}
         *
         * @example
         * error.line       //=> 2
         * error.input.line //=> 4
         */
        _this.line = line;
        /**
         * Source column of the error.
         *
         * @type {number}
         *
         * @example
         * error.column       //=> 1
         * error.input.column //=> 4
         */

        _this.column = column;
      }

      _this.setMessage();

      if (Error.captureStackTrace) {
        Error.captureStackTrace(_assertThisInitialized(_this), CssSyntaxError);
      }

      return _this;
    }

    var _proto = CssSyntaxError.prototype;

    _proto.setMessage = function setMessage() {
      /**
       * Full error text in the GNU error format
       * with plugin, file, line and column.
       *
       * @type {string}
       *
       * @example
       * error.message //=> 'a.css:1:1: Unclosed block'
       */
      this.message = this.plugin ? this.plugin + ': ' : '';
      this.message += this.file ? this.file : '<css input>';

      if (typeof this.line !== 'undefined') {
        this.message += ':' + this.line + ':' + this.column;
      }

      this.message += ': ' + this.reason;
    }
    /**
     * Returns a few lines of CSS source that caused the error.
     *
     * If the CSS has an input source map without `sourceContent`,
     * this method will return an empty string.
     *
     * @param {boolean} [color] Whether arrow will be colored red by terminal
     *                          color codes. By default, PostCSS will detect
     *                          color support by `process.stdout.isTTY`
     *                          and `process.env.NODE_DISABLE_COLORS`.
     *
     * @example
     * error.showSourceCode() //=> "  4 | }
     *                        //      5 | a {
     *                        //    > 6 |   bad
     *                        //        |   ^
     *                        //      7 | }
     *                        //      8 | b {"
     *
     * @return {string} Few lines of CSS source that caused the error.
     */
    ;

    _proto.showSourceCode = function showSourceCode(color) {
      var _this2 = this;

      if (!this.source) return '';
      var css = this.source;

      if (_terminalHighlight.default) {
        if (typeof color === 'undefined') color = _supportsColor.default.stdout;
        if (color) css = (0, _terminalHighlight.default)(css);
      }

      var lines = css.split(/\r?\n/);
      var start = Math.max(this.line - 3, 0);
      var end = Math.min(this.line + 2, lines.length);
      var maxWidth = String(end).length;

      function mark(text) {
        if (color && _chalk.default.red) {
          return _chalk.default.red.bold(text);
        }

        return text;
      }

      function aside(text) {
        if (color && _chalk.default.gray) {
          return _chalk.default.gray(text);
        }

        return text;
      }

      return lines.slice(start, end).map(function (line, index) {
        var number = start + 1 + index;
        var gutter = ' ' + (' ' + number).slice(-maxWidth) + ' | ';

        if (number === _this2.line) {
          var spacing = aside(gutter.replace(/\d/g, ' ')) + line.slice(0, _this2.column - 1).replace(/[^\t]/g, ' ');
          return mark('>') + aside(gutter) + line + '\n ' + spacing + mark('^');
        }

        return ' ' + aside(gutter) + line;
      }).join('\n');
    }
    /**
     * Returns error position, message and source code of the broken part.
     *
     * @example
     * error.toString() //=> "CssSyntaxError: app.css:1:1: Unclosed block
     *                  //    > 1 | a {
     *                  //        | ^"
     *
     * @return {string} Error position, message and source code.
     */
    ;

    _proto.toString = function toString() {
      var code = this.showSourceCode();

      if (code) {
        code = '\n\n' + code + '\n';
      }

      return this.name + ': ' + this.message + code;
    }
    /**
     * @memberof CssSyntaxError#
     * @member {Input} input Input object with PostCSS internal information
     *                       about input file. If input has source map
     *                       from previous tool, PostCSS will use origin
     *                       (for example, Sass) source. You can use this
     *                       object to get PostCSS input source.
     *
     * @example
     * error.input.file //=> 'a.css'
     * error.file       //=> 'a.sass'
     */
    ;

    return CssSyntaxError;
  }(_wrapNativeSuper(Error));

  var _default = CssSyntaxError;
  exports.default = _default;
  module.exports = exports.default;

  });

  var stringifier = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;
  var DEFAULT_RAW = {
    colon: ': ',
    indent: '    ',
    beforeDecl: '\n',
    beforeRule: '\n',
    beforeOpen: ' ',
    beforeClose: '\n',
    beforeComment: '\n',
    after: '\n',
    emptyBody: '',
    commentLeft: ' ',
    commentRight: ' ',
    semicolon: false
  };

  function capitalize(str) {
    return str[0].toUpperCase() + str.slice(1);
  }

  var Stringifier =
  /*#__PURE__*/
  function () {
    function Stringifier(builder) {
      this.builder = builder;
    }

    var _proto = Stringifier.prototype;

    _proto.stringify = function stringify(node, semicolon) {
      this[node.type](node, semicolon);
    };

    _proto.root = function root(node) {
      this.body(node);
      if (node.raws.after) this.builder(node.raws.after);
    };

    _proto.comment = function comment(node) {
      var left = this.raw(node, 'left', 'commentLeft');
      var right = this.raw(node, 'right', 'commentRight');
      this.builder('/*' + left + node.text + right + '*/', node);
    };

    _proto.decl = function decl(node, semicolon) {
      var between = this.raw(node, 'between', 'colon');
      var string = node.prop + between + this.rawValue(node, 'value');

      if (node.important) {
        string += node.raws.important || ' !important';
      }

      if (semicolon) string += ';';
      this.builder(string, node);
    };

    _proto.rule = function rule(node) {
      this.block(node, this.rawValue(node, 'selector'));

      if (node.raws.ownSemicolon) {
        this.builder(node.raws.ownSemicolon, node, 'end');
      }
    };

    _proto.atrule = function atrule(node, semicolon) {
      var name = '@' + node.name;
      var params = node.params ? this.rawValue(node, 'params') : '';

      if (typeof node.raws.afterName !== 'undefined') {
        name += node.raws.afterName;
      } else if (params) {
        name += ' ';
      }

      if (node.nodes) {
        this.block(node, name + params);
      } else {
        var end = (node.raws.between || '') + (semicolon ? ';' : '');
        this.builder(name + params + end, node);
      }
    };

    _proto.body = function body(node) {
      var last = node.nodes.length - 1;

      while (last > 0) {
        if (node.nodes[last].type !== 'comment') break;
        last -= 1;
      }

      var semicolon = this.raw(node, 'semicolon');

      for (var i = 0; i < node.nodes.length; i++) {
        var child = node.nodes[i];
        var before = this.raw(child, 'before');
        if (before) this.builder(before);
        this.stringify(child, last !== i || semicolon);
      }
    };

    _proto.block = function block(node, start) {
      var between = this.raw(node, 'between', 'beforeOpen');
      this.builder(start + between + '{', node, 'start');
      var after;

      if (node.nodes && node.nodes.length) {
        this.body(node);
        after = this.raw(node, 'after');
      } else {
        after = this.raw(node, 'after', 'emptyBody');
      }

      if (after) this.builder(after);
      this.builder('}', node, 'end');
    };

    _proto.raw = function raw(node, own, detect) {
      var value;
      if (!detect) detect = own; // Already had

      if (own) {
        value = node.raws[own];
        if (typeof value !== 'undefined') return value;
      }

      var parent = node.parent; // Hack for first rule in CSS

      if (detect === 'before') {
        if (!parent || parent.type === 'root' && parent.first === node) {
          return '';
        }
      } // Floating child without parent


      if (!parent) return DEFAULT_RAW[detect]; // Detect style by other nodes

      var root = node.root();
      if (!root.rawCache) root.rawCache = {};

      if (typeof root.rawCache[detect] !== 'undefined') {
        return root.rawCache[detect];
      }

      if (detect === 'before' || detect === 'after') {
        return this.beforeAfter(node, detect);
      } else {
        var method = 'raw' + capitalize(detect);

        if (this[method]) {
          value = this[method](root, node);
        } else {
          root.walk(function (i) {
            value = i.raws[own];
            if (typeof value !== 'undefined') return false;
          });
        }
      }

      if (typeof value === 'undefined') value = DEFAULT_RAW[detect];
      root.rawCache[detect] = value;
      return value;
    };

    _proto.rawSemicolon = function rawSemicolon(root) {
      var value;
      root.walk(function (i) {
        if (i.nodes && i.nodes.length && i.last.type === 'decl') {
          value = i.raws.semicolon;
          if (typeof value !== 'undefined') return false;
        }
      });
      return value;
    };

    _proto.rawEmptyBody = function rawEmptyBody(root) {
      var value;
      root.walk(function (i) {
        if (i.nodes && i.nodes.length === 0) {
          value = i.raws.after;
          if (typeof value !== 'undefined') return false;
        }
      });
      return value;
    };

    _proto.rawIndent = function rawIndent(root) {
      if (root.raws.indent) return root.raws.indent;
      var value;
      root.walk(function (i) {
        var p = i.parent;

        if (p && p !== root && p.parent && p.parent === root) {
          if (typeof i.raws.before !== 'undefined') {
            var parts = i.raws.before.split('\n');
            value = parts[parts.length - 1];
            value = value.replace(/[^\s]/g, '');
            return false;
          }
        }
      });
      return value;
    };

    _proto.rawBeforeComment = function rawBeforeComment(root, node) {
      var value;
      root.walkComments(function (i) {
        if (typeof i.raws.before !== 'undefined') {
          value = i.raws.before;

          if (value.indexOf('\n') !== -1) {
            value = value.replace(/[^\n]+$/, '');
          }

          return false;
        }
      });

      if (typeof value === 'undefined') {
        value = this.raw(node, null, 'beforeDecl');
      } else if (value) {
        value = value.replace(/[^\s]/g, '');
      }

      return value;
    };

    _proto.rawBeforeDecl = function rawBeforeDecl(root, node) {
      var value;
      root.walkDecls(function (i) {
        if (typeof i.raws.before !== 'undefined') {
          value = i.raws.before;

          if (value.indexOf('\n') !== -1) {
            value = value.replace(/[^\n]+$/, '');
          }

          return false;
        }
      });

      if (typeof value === 'undefined') {
        value = this.raw(node, null, 'beforeRule');
      } else if (value) {
        value = value.replace(/[^\s]/g, '');
      }

      return value;
    };

    _proto.rawBeforeRule = function rawBeforeRule(root) {
      var value;
      root.walk(function (i) {
        if (i.nodes && (i.parent !== root || root.first !== i)) {
          if (typeof i.raws.before !== 'undefined') {
            value = i.raws.before;

            if (value.indexOf('\n') !== -1) {
              value = value.replace(/[^\n]+$/, '');
            }

            return false;
          }
        }
      });
      if (value) value = value.replace(/[^\s]/g, '');
      return value;
    };

    _proto.rawBeforeClose = function rawBeforeClose(root) {
      var value;
      root.walk(function (i) {
        if (i.nodes && i.nodes.length > 0) {
          if (typeof i.raws.after !== 'undefined') {
            value = i.raws.after;

            if (value.indexOf('\n') !== -1) {
              value = value.replace(/[^\n]+$/, '');
            }

            return false;
          }
        }
      });
      if (value) value = value.replace(/[^\s]/g, '');
      return value;
    };

    _proto.rawBeforeOpen = function rawBeforeOpen(root) {
      var value;
      root.walk(function (i) {
        if (i.type !== 'decl') {
          value = i.raws.between;
          if (typeof value !== 'undefined') return false;
        }
      });
      return value;
    };

    _proto.rawColon = function rawColon(root) {
      var value;
      root.walkDecls(function (i) {
        if (typeof i.raws.between !== 'undefined') {
          value = i.raws.between.replace(/[^\s:]/g, '');
          return false;
        }
      });
      return value;
    };

    _proto.beforeAfter = function beforeAfter(node, detect) {
      var value;

      if (node.type === 'decl') {
        value = this.raw(node, null, 'beforeDecl');
      } else if (node.type === 'comment') {
        value = this.raw(node, null, 'beforeComment');
      } else if (detect === 'before') {
        value = this.raw(node, null, 'beforeRule');
      } else {
        value = this.raw(node, null, 'beforeClose');
      }

      var buf = node.parent;
      var depth = 0;

      while (buf && buf.type !== 'root') {
        depth += 1;
        buf = buf.parent;
      }

      if (value.indexOf('\n') !== -1) {
        var indent = this.raw(node, null, 'indent');

        if (indent.length) {
          for (var step = 0; step < depth; step++) {
            value += indent;
          }
        }
      }

      return value;
    };

    _proto.rawValue = function rawValue(node, prop) {
      var value = node[prop];
      var raw = node.raws[prop];

      if (raw && raw.value === value) {
        return raw.raw;
      }

      return value;
    };

    return Stringifier;
  }();

  var _default = Stringifier;
  exports.default = _default;
  module.exports = exports.default;

  });

  var stringify_1 = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _stringifier = _interopRequireDefault(stringifier);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function stringify(node, builder) {
    var str = new _stringifier.default(builder);
    str.stringify(node);
  }

  var _default = stringify;
  exports.default = _default;
  module.exports = exports.default;

  });

  var node = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _cssSyntaxError = _interopRequireDefault(cssSyntaxError);

  var _stringifier = _interopRequireDefault(stringifier);

  var _stringify = _interopRequireDefault(stringify_1);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function cloneNode(obj, parent) {
    var cloned = new obj.constructor();

    for (var i in obj) {
      if (!obj.hasOwnProperty(i)) continue;
      var value = obj[i];
      var type = typeof value;

      if (i === 'parent' && type === 'object') {
        if (parent) cloned[i] = parent;
      } else if (i === 'source') {
        cloned[i] = value;
      } else if (value instanceof Array) {
        cloned[i] = value.map(function (j) {
          return cloneNode(j, cloned);
        });
      } else {
        if (type === 'object' && value !== null) value = cloneNode(value);
        cloned[i] = value;
      }
    }

    return cloned;
  }
  /**
   * All node classes inherit the following common methods.
   *
   * @abstract
   */


  var Node =
  /*#__PURE__*/
  function () {
    /**
     * @param {object} [defaults] Value for node properties.
     */
    function Node(defaults) {
      if (defaults === void 0) {
        defaults = {};
      }

      this.raws = {};

      if (process.env.NODE_ENV !== 'production') {
        if (typeof defaults !== 'object' && typeof defaults !== 'undefined') {
          throw new Error('PostCSS nodes constructor accepts object, not ' + JSON.stringify(defaults));
        }
      }

      for (var name in defaults) {
        this[name] = defaults[name];
      }
    }
    /**
     * Returns a `CssSyntaxError` instance containing the original position
     * of the node in the source, showing line and column numbers and also
     * a small excerpt to facilitate debugging.
     *
     * If present, an input source map will be used to get the original position
     * of the source, even from a previous compilation step
     * (e.g., from Sass compilation).
     *
     * This method produces very useful error messages.
     *
     * @param {string} message     Error description.
     * @param {object} [opts]      Options.
     * @param {string} opts.plugin Plugin name that created this error.
     *                             PostCSS will set it automatically.
     * @param {string} opts.word   A word inside a node’s string that should
     *                             be highlighted as the source of the error.
     * @param {number} opts.index  An index inside a node’s string that should
     *                             be highlighted as the source of the error.
     *
     * @return {CssSyntaxError} Error object to throw it.
     *
     * @example
     * if (!variables[name]) {
     *   throw decl.error('Unknown variable ' + name, { word: name })
     *   // CssSyntaxError: postcss-vars:a.sass:4:3: Unknown variable $black
     *   //   color: $black
     *   // a
     *   //          ^
     *   //   background: white
     * }
     */


    var _proto = Node.prototype;

    _proto.error = function error(message, opts) {
      if (opts === void 0) {
        opts = {};
      }

      if (this.source) {
        var pos = this.positionBy(opts);
        return this.source.input.error(message, pos.line, pos.column, opts);
      }

      return new _cssSyntaxError.default(message);
    }
    /**
     * This method is provided as a convenience wrapper for {@link Result#warn}.
     *
     * @param {Result} result      The {@link Result} instance
     *                             that will receive the warning.
     * @param {string} text        Warning message.
     * @param {object} [opts]      Options
     * @param {string} opts.plugin Plugin name that created this warning.
     *                             PostCSS will set it automatically.
     * @param {string} opts.word   A word inside a node’s string that should
     *                             be highlighted as the source of the warning.
     * @param {number} opts.index  An index inside a node’s string that should
     *                             be highlighted as the source of the warning.
     *
     * @return {Warning} Created warning object.
     *
     * @example
     * const plugin = postcss.plugin('postcss-deprecated', () => {
     *   return (root, result) => {
     *     root.walkDecls('bad', decl => {
     *       decl.warn(result, 'Deprecated property bad')
     *     })
     *   }
     * })
     */
    ;

    _proto.warn = function warn(result, text, opts) {
      var data = {
        node: this
      };

      for (var i in opts) {
        data[i] = opts[i];
      }

      return result.warn(text, data);
    }
    /**
     * Removes the node from its parent and cleans the parent properties
     * from the node and its children.
     *
     * @example
     * if (decl.prop.match(/^-webkit-/)) {
     *   decl.remove()
     * }
     *
     * @return {Node} Node to make calls chain.
     */
    ;

    _proto.remove = function remove() {
      if (this.parent) {
        this.parent.removeChild(this);
      }

      this.parent = undefined;
      return this;
    }
    /**
     * Returns a CSS string representing the node.
     *
     * @param {stringifier|syntax} [stringifier] A syntax to use
     *                                           in string generation.
     *
     * @return {string} CSS string of this node.
     *
     * @example
     * postcss.rule({ selector: 'a' }).toString() //=> "a {}"
     */
    ;

    _proto.toString = function toString(stringifier) {
      if (stringifier === void 0) {
        stringifier = _stringify.default;
      }

      if (stringifier.stringify) stringifier = stringifier.stringify;
      var result = '';
      stringifier(this, function (i) {
        result += i;
      });
      return result;
    }
    /**
     * Returns an exact clone of the node.
     *
     * The resulting cloned node and its (cloned) children will retain
     * code style properties.
     *
     * @param {object} [overrides] New properties to override in the clone.
     *
     * @example
     * decl.raws.before    //=> "\n  "
     * const cloned = decl.clone({ prop: '-moz-' + decl.prop })
     * cloned.raws.before  //=> "\n  "
     * cloned.toString()   //=> -moz-transform: scale(0)
     *
     * @return {Node} Clone of the node.
     */
    ;

    _proto.clone = function clone(overrides) {
      if (overrides === void 0) {
        overrides = {};
      }

      var cloned = cloneNode(this);

      for (var name in overrides) {
        cloned[name] = overrides[name];
      }

      return cloned;
    }
    /**
     * Shortcut to clone the node and insert the resulting cloned node
     * before the current node.
     *
     * @param {object} [overrides] Mew properties to override in the clone.
     *
     * @example
     * decl.cloneBefore({ prop: '-moz-' + decl.prop })
     *
     * @return {Node} New node
     */
    ;

    _proto.cloneBefore = function cloneBefore(overrides) {
      if (overrides === void 0) {
        overrides = {};
      }

      var cloned = this.clone(overrides);
      this.parent.insertBefore(this, cloned);
      return cloned;
    }
    /**
     * Shortcut to clone the node and insert the resulting cloned node
     * after the current node.
     *
     * @param {object} [overrides] New properties to override in the clone.
     *
     * @return {Node} New node.
     */
    ;

    _proto.cloneAfter = function cloneAfter(overrides) {
      if (overrides === void 0) {
        overrides = {};
      }

      var cloned = this.clone(overrides);
      this.parent.insertAfter(this, cloned);
      return cloned;
    }
    /**
     * Inserts node(s) before the current node and removes the current node.
     *
     * @param {...Node} nodes Mode(s) to replace current one.
     *
     * @example
     * if (atrule.name === 'mixin') {
     *   atrule.replaceWith(mixinRules[atrule.params])
     * }
     *
     * @return {Node} Current node to methods chain.
     */
    ;

    _proto.replaceWith = function replaceWith() {
      if (this.parent) {
        for (var _len = arguments.length, nodes = new Array(_len), _key = 0; _key < _len; _key++) {
          nodes[_key] = arguments[_key];
        }

        for (var _i = 0, _nodes = nodes; _i < _nodes.length; _i++) {
          var node = _nodes[_i];
          this.parent.insertBefore(this, node);
        }

        this.remove();
      }

      return this;
    }
    /**
     * Returns the next child of the node’s parent.
     * Returns `undefined` if the current node is the last child.
     *
     * @return {Node|undefined} Next node.
     *
     * @example
     * if (comment.text === 'delete next') {
     *   const next = comment.next()
     *   if (next) {
     *     next.remove()
     *   }
     * }
     */
    ;

    _proto.next = function next() {
      if (!this.parent) return undefined;
      var index = this.parent.index(this);
      return this.parent.nodes[index + 1];
    }
    /**
     * Returns the previous child of the node’s parent.
     * Returns `undefined` if the current node is the first child.
     *
     * @return {Node|undefined} Previous node.
     *
     * @example
     * const annotation = decl.prev()
     * if (annotation.type === 'comment') {
     *   readAnnotation(annotation.text)
     * }
     */
    ;

    _proto.prev = function prev() {
      if (!this.parent) return undefined;
      var index = this.parent.index(this);
      return this.parent.nodes[index - 1];
    }
    /**
     * Insert new node before current node to current node’s parent.
     *
     * Just alias for `node.parent.insertBefore(node, add)`.
     *
     * @param {Node|object|string|Node[]} add New node.
     *
     * @return {Node} This node for methods chain.
     *
     * @example
     * decl.before('content: ""')
     */
    ;

    _proto.before = function before(add) {
      this.parent.insertBefore(this, add);
      return this;
    }
    /**
     * Insert new node after current node to current node’s parent.
     *
     * Just alias for `node.parent.insertAfter(node, add)`.
     *
     * @param {Node|object|string|Node[]} add New node.
     *
     * @return {Node} This node for methods chain.
     *
     * @example
     * decl.after('color: black')
     */
    ;

    _proto.after = function after(add) {
      this.parent.insertAfter(this, add);
      return this;
    };

    _proto.toJSON = function toJSON() {
      var fixed = {};

      for (var name in this) {
        if (!this.hasOwnProperty(name)) continue;
        if (name === 'parent') continue;
        var value = this[name];

        if (value instanceof Array) {
          fixed[name] = value.map(function (i) {
            if (typeof i === 'object' && i.toJSON) {
              return i.toJSON();
            } else {
              return i;
            }
          });
        } else if (typeof value === 'object' && value.toJSON) {
          fixed[name] = value.toJSON();
        } else {
          fixed[name] = value;
        }
      }

      return fixed;
    }
    /**
     * Returns a {@link Node#raws} value. If the node is missing
     * the code style property (because the node was manually built or cloned),
     * PostCSS will try to autodetect the code style property by looking
     * at other nodes in the tree.
     *
     * @param {string} prop          Name of code style property.
     * @param {string} [defaultType] Name of default value, it can be missed
     *                               if the value is the same as prop.
     *
     * @example
     * const root = postcss.parse('a { background: white }')
     * root.nodes[0].append({ prop: 'color', value: 'black' })
     * root.nodes[0].nodes[1].raws.before   //=> undefined
     * root.nodes[0].nodes[1].raw('before') //=> ' '
     *
     * @return {string} Code style value.
     */
    ;

    _proto.raw = function raw(prop, defaultType) {
      var str = new _stringifier.default();
      return str.raw(this, prop, defaultType);
    }
    /**
     * Finds the Root instance of the node’s tree.
     *
     * @example
     * root.nodes[0].nodes[0].root() === root
     *
     * @return {Root} Root parent.
     */
    ;

    _proto.root = function root() {
      var result = this;

      while (result.parent) {
        result = result.parent;
      }

      return result;
    }
    /**
     * Clear the code style properties for the node and its children.
     *
     * @param {boolean} [keepBetween] Keep the raws.between symbols.
     *
     * @return {undefined}
     *
     * @example
     * node.raws.before  //=> ' '
     * node.cleanRaws()
     * node.raws.before  //=> undefined
     */
    ;

    _proto.cleanRaws = function cleanRaws(keepBetween) {
      delete this.raws.before;
      delete this.raws.after;
      if (!keepBetween) delete this.raws.between;
    };

    _proto.positionInside = function positionInside(index) {
      var string = this.toString();
      var column = this.source.start.column;
      var line = this.source.start.line;

      for (var i = 0; i < index; i++) {
        if (string[i] === '\n') {
          column = 1;
          line += 1;
        } else {
          column += 1;
        }
      }

      return {
        line: line,
        column: column
      };
    };

    _proto.positionBy = function positionBy(opts) {
      var pos = this.source.start;

      if (opts.index) {
        pos = this.positionInside(opts.index);
      } else if (opts.word) {
        var index = this.toString().indexOf(opts.word);
        if (index !== -1) pos = this.positionInside(index);
      }

      return pos;
    }
    /**
     * @memberof Node#
     * @member {string} type String representing the node’s type.
     *                       Possible values are `root`, `atrule`, `rule`,
     *                       `decl`, or `comment`.
     *
     * @example
     * postcss.decl({ prop: 'color', value: 'black' }).type //=> 'decl'
     */

    /**
     * @memberof Node#
     * @member {Container} parent The node’s parent node.
     *
     * @example
     * root.nodes[0].parent === root
     */

    /**
     * @memberof Node#
     * @member {source} source The input source of the node.
     *
     * The property is used in source map generation.
     *
     * If you create a node manually (e.g., with `postcss.decl()`),
     * that node will not have a `source` property and will be absent
     * from the source map. For this reason, the plugin developer should
     * consider cloning nodes to create new ones (in which case the new node’s
     * source will reference the original, cloned node) or setting
     * the `source` property manually.
     *
     * ```js
     * // Bad
     * const prefixed = postcss.decl({
     *   prop: '-moz-' + decl.prop,
     *   value: decl.value
     * })
     *
     * // Good
     * const prefixed = decl.clone({ prop: '-moz-' + decl.prop })
     * ```
     *
     * ```js
     * if (atrule.name === 'add-link') {
     *   const rule = postcss.rule({ selector: 'a', source: atrule.source })
     *   atrule.parent.insertBefore(atrule, rule)
     * }
     * ```
     *
     * @example
     * decl.source.input.from //=> '/home/ai/a.sass'
     * decl.source.start      //=> { line: 10, column: 2 }
     * decl.source.end        //=> { line: 10, column: 12 }
     */

    /**
     * @memberof Node#
     * @member {object} raws Information to generate byte-to-byte equal
     *                       node string as it was in the origin input.
     *
     * Every parser saves its own properties,
     * but the default CSS parser uses:
     *
     * * `before`: the space symbols before the node. It also stores `*`
     *   and `_` symbols before the declaration (IE hack).
     * * `after`: the space symbols after the last child of the node
     *   to the end of the node.
     * * `between`: the symbols between the property and value
     *   for declarations, selector and `{` for rules, or last parameter
     *   and `{` for at-rules.
     * * `semicolon`: contains true if the last child has
     *   an (optional) semicolon.
     * * `afterName`: the space between the at-rule name and its parameters.
     * * `left`: the space symbols between `/*` and the comment’s text.
     * * `right`: the space symbols between the comment’s text
     *   and <code>*&#47;</code>.
     * * `important`: the content of the important statement,
     *   if it is not just `!important`.
     *
     * PostCSS cleans selectors, declaration values and at-rule parameters
     * from comments and extra spaces, but it stores origin content in raws
     * properties. As such, if you don’t change a declaration’s value,
     * PostCSS will use the raw value with comments.
     *
     * @example
     * const root = postcss.parse('a {\n  color:black\n}')
     * root.first.first.raws //=> { before: '\n  ', between: ':' }
     */
    ;

    return Node;
  }();

  var _default = Node;
  /**
   * @typedef {object} position
   * @property {number} line   Source line in file.
   * @property {number} column Source column in file.
   */

  /**
   * @typedef {object} source
   * @property {Input} input    {@link Input} with input file
   * @property {position} start The starting position of the node’s source.
   * @property {position} end   The ending position of the node’s source.
   */

  exports.default = _default;
  module.exports = exports.default;

  });

  var declaration = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _node = _interopRequireDefault(node);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

  /**
   * Represents a CSS declaration.
   *
   * @extends Node
   *
   * @example
   * const root = postcss.parse('a { color: black }')
   * const decl = root.first.first
   * decl.type       //=> 'decl'
   * decl.toString() //=> ' color: black'
   */
  var Declaration =
  /*#__PURE__*/
  function (_Node) {
    _inheritsLoose(Declaration, _Node);

    function Declaration(defaults) {
      var _this;

      _this = _Node.call(this, defaults) || this;
      _this.type = 'decl';
      return _this;
    }
    /**
     * @memberof Declaration#
     * @member {string} prop The declaration’s property name.
     *
     * @example
     * const root = postcss.parse('a { color: black }')
     * const decl = root.first.first
     * decl.prop //=> 'color'
     */

    /**
     * @memberof Declaration#
     * @member {string} value The declaration’s value.
     *
     * @example
     * const root = postcss.parse('a { color: black }')
     * const decl = root.first.first
     * decl.value //=> 'black'
     */

    /**
     * @memberof Declaration#
     * @member {boolean} important `true` if the declaration
     *                             has an !important annotation.
     *
     * @example
     * const root = postcss.parse('a { color: black !important; color: red }')
     * root.first.first.important //=> true
     * root.first.last.important  //=> undefined
     */

    /**
     * @memberof Declaration#
     * @member {object} raws Information to generate byte-to-byte equal
     *                       node string as it was in the origin input.
     *
     * Every parser saves its own properties,
     * but the default CSS parser uses:
     *
     * * `before`: the space symbols before the node. It also stores `*`
     *   and `_` symbols before the declaration (IE hack).
     * * `between`: the symbols between the property and value
     *   for declarations.
     * * `important`: the content of the important statement,
     *   if it is not just `!important`.
     *
     * PostCSS cleans declaration from comments and extra spaces,
     * but it stores origin content in raws properties.
     * As such, if you don’t change a declaration’s value,
     * PostCSS will use the raw value with comments.
     *
     * @example
     * const root = postcss.parse('a {\n  color:black\n}')
     * root.first.first.raws //=> { before: '\n  ', between: ':' }
     */


    return Declaration;
  }(_node.default);

  var _default = Declaration;
  exports.default = _default;
  module.exports = exports.default;

  });

  var mapGenerator = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _sourceMap = _interopRequireDefault(sourceMap);

  var _path = _interopRequireDefault(path__default['default']);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  var MapGenerator =
  /*#__PURE__*/
  function () {
    function MapGenerator(stringify, root, opts) {
      this.stringify = stringify;
      this.mapOpts = opts.map || {};
      this.root = root;
      this.opts = opts;
    }

    var _proto = MapGenerator.prototype;

    _proto.isMap = function isMap() {
      if (typeof this.opts.map !== 'undefined') {
        return !!this.opts.map;
      }

      return this.previous().length > 0;
    };

    _proto.previous = function previous() {
      var _this = this;

      if (!this.previousMaps) {
        this.previousMaps = [];
        this.root.walk(function (node) {
          if (node.source && node.source.input.map) {
            var map = node.source.input.map;

            if (_this.previousMaps.indexOf(map) === -1) {
              _this.previousMaps.push(map);
            }
          }
        });
      }

      return this.previousMaps;
    };

    _proto.isInline = function isInline() {
      if (typeof this.mapOpts.inline !== 'undefined') {
        return this.mapOpts.inline;
      }

      var annotation = this.mapOpts.annotation;

      if (typeof annotation !== 'undefined' && annotation !== true) {
        return false;
      }

      if (this.previous().length) {
        return this.previous().some(function (i) {
          return i.inline;
        });
      }

      return true;
    };

    _proto.isSourcesContent = function isSourcesContent() {
      if (typeof this.mapOpts.sourcesContent !== 'undefined') {
        return this.mapOpts.sourcesContent;
      }

      if (this.previous().length) {
        return this.previous().some(function (i) {
          return i.withContent();
        });
      }

      return true;
    };

    _proto.clearAnnotation = function clearAnnotation() {
      if (this.mapOpts.annotation === false) return;
      var node;

      for (var i = this.root.nodes.length - 1; i >= 0; i--) {
        node = this.root.nodes[i];
        if (node.type !== 'comment') continue;

        if (node.text.indexOf('# sourceMappingURL=') === 0) {
          this.root.removeChild(i);
        }
      }
    };

    _proto.setSourcesContent = function setSourcesContent() {
      var _this2 = this;

      var already = {};
      this.root.walk(function (node) {
        if (node.source) {
          var from = node.source.input.from;

          if (from && !already[from]) {
            already[from] = true;

            var relative = _this2.relative(from);

            _this2.map.setSourceContent(relative, node.source.input.css);
          }
        }
      });
    };

    _proto.applyPrevMaps = function applyPrevMaps() {
      for (var _iterator = this.previous(), _isArray = Array.isArray(_iterator), _i = 0, _iterator = _isArray ? _iterator : _iterator[Symbol.iterator]();;) {
        var _ref;

        if (_isArray) {
          if (_i >= _iterator.length) break;
          _ref = _iterator[_i++];
        } else {
          _i = _iterator.next();
          if (_i.done) break;
          _ref = _i.value;
        }

        var prev = _ref;
        var from = this.relative(prev.file);

        var root = prev.root || _path.default.dirname(prev.file);

        var map = void 0;

        if (this.mapOpts.sourcesContent === false) {
          map = new _sourceMap.default.SourceMapConsumer(prev.text);

          if (map.sourcesContent) {
            map.sourcesContent = map.sourcesContent.map(function () {
              return null;
            });
          }
        } else {
          map = prev.consumer();
        }

        this.map.applySourceMap(map, from, this.relative(root));
      }
    };

    _proto.isAnnotation = function isAnnotation() {
      if (this.isInline()) {
        return true;
      }

      if (typeof this.mapOpts.annotation !== 'undefined') {
        return this.mapOpts.annotation;
      }

      if (this.previous().length) {
        return this.previous().some(function (i) {
          return i.annotation;
        });
      }

      return true;
    };

    _proto.toBase64 = function toBase64(str) {
      if (Buffer) {
        return Buffer.from(str).toString('base64');
      }

      return window.btoa(unescape(encodeURIComponent(str)));
    };

    _proto.addAnnotation = function addAnnotation() {
      var content;

      if (this.isInline()) {
        content = 'data:application/json;base64,' + this.toBase64(this.map.toString());
      } else if (typeof this.mapOpts.annotation === 'string') {
        content = this.mapOpts.annotation;
      } else {
        content = this.outputFile() + '.map';
      }

      var eol = '\n';
      if (this.css.indexOf('\r\n') !== -1) eol = '\r\n';
      this.css += eol + '/*# sourceMappingURL=' + content + ' */';
    };

    _proto.outputFile = function outputFile() {
      if (this.opts.to) {
        return this.relative(this.opts.to);
      }

      if (this.opts.from) {
        return this.relative(this.opts.from);
      }

      return 'to.css';
    };

    _proto.generateMap = function generateMap() {
      this.generateString();
      if (this.isSourcesContent()) this.setSourcesContent();
      if (this.previous().length > 0) this.applyPrevMaps();
      if (this.isAnnotation()) this.addAnnotation();

      if (this.isInline()) {
        return [this.css];
      }

      return [this.css, this.map];
    };

    _proto.relative = function relative(file) {
      if (file.indexOf('<') === 0) return file;
      if (/^\w+:\/\//.test(file)) return file;
      var from = this.opts.to ? _path.default.dirname(this.opts.to) : '.';

      if (typeof this.mapOpts.annotation === 'string') {
        from = _path.default.dirname(_path.default.resolve(from, this.mapOpts.annotation));
      }

      file = _path.default.relative(from, file);

      if (_path.default.sep === '\\') {
        return file.replace(/\\/g, '/');
      }

      return file;
    };

    _proto.sourcePath = function sourcePath(node) {
      if (this.mapOpts.from) {
        return this.mapOpts.from;
      }

      return this.relative(node.source.input.from);
    };

    _proto.generateString = function generateString() {
      var _this3 = this;

      this.css = '';
      this.map = new _sourceMap.default.SourceMapGenerator({
        file: this.outputFile()
      });
      var line = 1;
      var column = 1;
      var lines, last;
      this.stringify(this.root, function (str, node, type) {
        _this3.css += str;

        if (node && type !== 'end') {
          if (node.source && node.source.start) {
            _this3.map.addMapping({
              source: _this3.sourcePath(node),
              generated: {
                line: line,
                column: column - 1
              },
              original: {
                line: node.source.start.line,
                column: node.source.start.column - 1
              }
            });
          } else {
            _this3.map.addMapping({
              source: '<no source>',
              original: {
                line: 1,
                column: 0
              },
              generated: {
                line: line,
                column: column - 1
              }
            });
          }
        }

        lines = str.match(/\n/g);

        if (lines) {
          line += lines.length;
          last = str.lastIndexOf('\n');
          column = str.length - last;
        } else {
          column += str.length;
        }

        if (node && type !== 'start') {
          var p = node.parent || {
            raws: {}
          };

          if (node.type !== 'decl' || node !== p.last || p.raws.semicolon) {
            if (node.source && node.source.end) {
              _this3.map.addMapping({
                source: _this3.sourcePath(node),
                generated: {
                  line: line,
                  column: column - 2
                },
                original: {
                  line: node.source.end.line,
                  column: node.source.end.column - 1
                }
              });
            } else {
              _this3.map.addMapping({
                source: '<no source>',
                original: {
                  line: 1,
                  column: 0
                },
                generated: {
                  line: line,
                  column: column - 1
                }
              });
            }
          }
        }
      });
    };

    _proto.generate = function generate() {
      this.clearAnnotation();

      if (this.isMap()) {
        return this.generateMap();
      }

      var result = '';
      this.stringify(this.root, function (i) {
        result += i;
      });
      return [result];
    };

    return MapGenerator;
  }();

  var _default = MapGenerator;
  exports.default = _default;
  module.exports = exports.default;

  });

  var warnOnce_1 = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = warnOnce;
  var printed = {};

  function warnOnce(message) {
    if (printed[message]) return;
    printed[message] = true;

    if (typeof console !== 'undefined' && console.warn) {
      console.warn(message);
    }
  }

  module.exports = exports.default;

  });

  var warning = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  /**
   * Represents a plugin’s warning. It can be created using {@link Node#warn}.
   *
   * @example
   * if (decl.important) {
   *   decl.warn(result, 'Avoid !important', { word: '!important' })
   * }
   */
  var Warning =
  /*#__PURE__*/
  function () {
    /**
     * @param {string} text        Warning message.
     * @param {Object} [opts]      Warning options.
     * @param {Node}   opts.node   CSS node that caused the warning.
     * @param {string} opts.word   Word in CSS source that caused the warning.
     * @param {number} opts.index  Index in CSS node string that caused
     *                             the warning.
     * @param {string} opts.plugin Name of the plugin that created
     *                             this warning. {@link Result#warn} fills
     *                             this property automatically.
     */
    function Warning(text, opts) {
      if (opts === void 0) {
        opts = {};
      }

      /**
       * Type to filter warnings from {@link Result#messages}.
       * Always equal to `"warning"`.
       *
       * @type {string}
       *
       * @example
       * const nonWarning = result.messages.filter(i => i.type !== 'warning')
       */
      this.type = 'warning';
      /**
       * The warning message.
       *
       * @type {string}
       *
       * @example
       * warning.text //=> 'Try to avoid !important'
       */

      this.text = text;

      if (opts.node && opts.node.source) {
        var pos = opts.node.positionBy(opts);
        /**
         * Line in the input file with this warning’s source.
         * @type {number}
         *
         * @example
         * warning.line //=> 5
         */

        this.line = pos.line;
        /**
         * Column in the input file with this warning’s source.
         *
         * @type {number}
         *
         * @example
         * warning.column //=> 6
         */

        this.column = pos.column;
      }

      for (var opt in opts) {
        this[opt] = opts[opt];
      }
    }
    /**
     * Returns a warning position and message.
     *
     * @example
     * warning.toString() //=> 'postcss-lint:a.css:10:14: Avoid !important'
     *
     * @return {string} Warning position and message.
     */


    var _proto = Warning.prototype;

    _proto.toString = function toString() {
      if (this.node) {
        return this.node.error(this.text, {
          plugin: this.plugin,
          index: this.index,
          word: this.word
        }).message;
      }

      if (this.plugin) {
        return this.plugin + ': ' + this.text;
      }

      return this.text;
    }
    /**
     * @memberof Warning#
     * @member {string} plugin The name of the plugin that created
     *                         it will fill this property automatically.
     *                         this warning. When you call {@link Node#warn}
     *
     * @example
     * warning.plugin //=> 'postcss-important'
     */

    /**
     * @memberof Warning#
     * @member {Node} node Contains the CSS node that caused the warning.
     *
     * @example
     * warning.node.toString() //=> 'color: white !important'
     */
    ;

    return Warning;
  }();

  var _default = Warning;
  exports.default = _default;
  module.exports = exports.default;

  });

  var result = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _warning = _interopRequireDefault(warning);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

  function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

  /**
   * Provides the result of the PostCSS transformations.
   *
   * A Result instance is returned by {@link LazyResult#then}
   * or {@link Root#toResult} methods.
   *
   * @example
   * postcss([autoprefixer]).process(css).then(result => {
   *  console.log(result.css)
   * })
   *
   * @example
   * const result2 = postcss.parse(css).toResult()
   */
  var Result =
  /*#__PURE__*/
  function () {
    /**
     * @param {Processor} processor Processor used for this transformation.
     * @param {Root}      root      Root node after all transformations.
     * @param {processOptions} opts Options from the {@link Processor#process}
     *                              or {@link Root#toResult}.
     */
    function Result(processor, root, opts) {
      /**
       * The Processor instance used for this transformation.
       *
       * @type {Processor}
       *
       * @example
       * for (const plugin of result.processor.plugins) {
       *   if (plugin.postcssPlugin === 'postcss-bad') {
       *     throw 'postcss-good is incompatible with postcss-bad'
       *   }
       * })
       */
      this.processor = processor;
      /**
       * Contains messages from plugins (e.g., warnings or custom messages).
       * Each message should have type and plugin properties.
       *
       * @type {Message[]}
       *
       * @example
       * postcss.plugin('postcss-min-browser', () => {
       *   return (root, result) => {
       *     const browsers = detectMinBrowsersByCanIUse(root)
       *     result.messages.push({
       *       type: 'min-browser',
       *       plugin: 'postcss-min-browser',
       *       browsers
       *     })
       *   }
       * })
       */

      this.messages = [];
      /**
       * Root node after all transformations.
       *
       * @type {Root}
       *
       * @example
       * root.toResult().root === root
       */

      this.root = root;
      /**
       * Options from the {@link Processor#process} or {@link Root#toResult} call
       * that produced this Result instance.
       *
       * @type {processOptions}
       *
       * @example
       * root.toResult(opts).opts === opts
       */

      this.opts = opts;
      /**
       * A CSS string representing of {@link Result#root}.
       *
       * @type {string}
       *
       * @example
       * postcss.parse('a{}').toResult().css //=> "a{}"
       */

      this.css = undefined;
      /**
       * An instance of `SourceMapGenerator` class from the `source-map` library,
       * representing changes to the {@link Result#root} instance.
       *
       * @type {SourceMapGenerator}
       *
       * @example
       * result.map.toJSON() //=> { version: 3, file: 'a.css', … }
       *
       * @example
       * if (result.map) {
       *   fs.writeFileSync(result.opts.to + '.map', result.map.toString())
       * }
       */

      this.map = undefined;
    }
    /**
     * Returns for @{link Result#css} content.
     *
     * @example
     * result + '' === result.css
     *
     * @return {string} String representing of {@link Result#root}.
     */


    var _proto = Result.prototype;

    _proto.toString = function toString() {
      return this.css;
    }
    /**
     * Creates an instance of {@link Warning} and adds it
     * to {@link Result#messages}.
     *
     * @param {string} text        Warning message.
     * @param {Object} [opts]      Warning options.
     * @param {Node}   opts.node   CSS node that caused the warning.
     * @param {string} opts.word   Word in CSS source that caused the warning.
     * @param {number} opts.index  Index in CSS node string that caused
     *                             the warning.
     * @param {string} opts.plugin Name of the plugin that created
     *                             this warning. {@link Result#warn} fills
     *                             this property automatically.
     *
     * @return {Warning} Created warning.
     */
    ;

    _proto.warn = function warn(text, opts) {
      if (opts === void 0) {
        opts = {};
      }

      if (!opts.plugin) {
        if (this.lastPlugin && this.lastPlugin.postcssPlugin) {
          opts.plugin = this.lastPlugin.postcssPlugin;
        }
      }

      var warning = new _warning.default(text, opts);
      this.messages.push(warning);
      return warning;
    }
    /**
       * Returns warnings from plugins. Filters {@link Warning} instances
       * from {@link Result#messages}.
       *
       * @example
       * result.warnings().forEach(warn => {
       *   console.warn(warn.toString())
       * })
       *
       * @return {Warning[]} Warnings from plugins.
       */
    ;

    _proto.warnings = function warnings() {
      return this.messages.filter(function (i) {
        return i.type === 'warning';
      });
    }
    /**
     * An alias for the {@link Result#css} property.
     * Use it with syntaxes that generate non-CSS output.
     *
     * @type {string}
     *
     * @example
     * result.css === result.content
     */
    ;

    _createClass(Result, [{
      key: "content",
      get: function get() {
        return this.css;
      }
    }]);

    return Result;
  }();

  var _default = Result;
  /**
   * @typedef  {object} Message
   * @property {string} type   Message type.
   * @property {string} plugin Source PostCSS plugin name.
   */

  exports.default = _default;
  module.exports = exports.default;

  });

  var comment = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _node = _interopRequireDefault(node);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

  /**
   * Represents a comment between declarations or statements (rule and at-rules).
   *
   * Comments inside selectors, at-rule parameters, or declaration values
   * will be stored in the `raws` properties explained above.
   *
   * @extends Node
   */
  var Comment =
  /*#__PURE__*/
  function (_Node) {
    _inheritsLoose(Comment, _Node);

    function Comment(defaults) {
      var _this;

      _this = _Node.call(this, defaults) || this;
      _this.type = 'comment';
      return _this;
    }
    /**
     * @memberof Comment#
     * @member {string} text The comment’s text.
     */

    /**
     * @memberof Comment#
     * @member {object} raws Information to generate byte-to-byte equal
     *                       node string as it was in the origin input.
     *
     * Every parser saves its own properties,
     * but the default CSS parser uses:
     *
     * * `before`: the space symbols before the node.
     * * `left`: the space symbols between `/*` and the comment’s text.
     * * `right`: the space symbols between the comment’s text.
     */


    return Comment;
  }(_node.default);

  var _default = Comment;
  exports.default = _default;
  module.exports = exports.default;

  });

  var list_1 = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  /**
   * Contains helpers for safely splitting lists of CSS values,
   * preserving parentheses and quotes.
   *
   * @example
   * const list = postcss.list
   *
   * @namespace list
   */
  var list = {
    split: function split(string, separators, last) {
      var array = [];
      var current = '';
      var split = false;
      var func = 0;
      var quote = false;
      var escape = false;

      for (var i = 0; i < string.length; i++) {
        var letter = string[i];

        if (quote) {
          if (escape) {
            escape = false;
          } else if (letter === '\\') {
            escape = true;
          } else if (letter === quote) {
            quote = false;
          }
        } else if (letter === '"' || letter === '\'') {
          quote = letter;
        } else if (letter === '(') {
          func += 1;
        } else if (letter === ')') {
          if (func > 0) func -= 1;
        } else if (func === 0) {
          if (separators.indexOf(letter) !== -1) split = true;
        }

        if (split) {
          if (current !== '') array.push(current.trim());
          current = '';
          split = false;
        } else {
          current += letter;
        }
      }

      if (last || current !== '') array.push(current.trim());
      return array;
    },

    /**
     * Safely splits space-separated values (such as those for `background`,
     * `border-radius`, and other shorthand properties).
     *
     * @param {string} string Space-separated values.
     *
     * @return {string[]} Split values.
     *
     * @example
     * postcss.list.space('1px calc(10% + 1px)') //=> ['1px', 'calc(10% + 1px)']
     */
    space: function space(string) {
      var spaces = [' ', '\n', '\t'];
      return list.split(string, spaces);
    },

    /**
     * Safely splits comma-separated values (such as those for `transition-*`
     * and `background` properties).
     *
     * @param {string} string Comma-separated values.
     *
     * @return {string[]} Split values.
     *
     * @example
     * postcss.list.comma('black, linear-gradient(white, black)')
     * //=> ['black', 'linear-gradient(white, black)']
     */
    comma: function comma(string) {
      return list.split(string, [','], true);
    }
  };
  var _default = list;
  exports.default = _default;
  module.exports = exports.default;

  });

  var rule = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _container = _interopRequireDefault(container);

  var _list = _interopRequireDefault(list_1);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

  function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

  function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

  /**
   * Represents a CSS rule: a selector followed by a declaration block.
   *
   * @extends Container
   *
   * @example
   * const root = postcss.parse('a{}')
   * const rule = root.first
   * rule.type       //=> 'rule'
   * rule.toString() //=> 'a{}'
   */
  var Rule =
  /*#__PURE__*/
  function (_Container) {
    _inheritsLoose(Rule, _Container);

    function Rule(defaults) {
      var _this;

      _this = _Container.call(this, defaults) || this;
      _this.type = 'rule';
      if (!_this.nodes) _this.nodes = [];
      return _this;
    }
    /**
     * An array containing the rule’s individual selectors.
     * Groups of selectors are split at commas.
     *
     * @type {string[]}
     *
     * @example
     * const root = postcss.parse('a, b { }')
     * const rule = root.first
     *
     * rule.selector  //=> 'a, b'
     * rule.selectors //=> ['a', 'b']
     *
     * rule.selectors = ['a', 'strong']
     * rule.selector //=> 'a, strong'
     */


    _createClass(Rule, [{
      key: "selectors",
      get: function get() {
        return _list.default.comma(this.selector);
      },
      set: function set(values) {
        var match = this.selector ? this.selector.match(/,\s*/) : null;
        var sep = match ? match[0] : ',' + this.raw('between', 'beforeOpen');
        this.selector = values.join(sep);
      }
      /**
       * @memberof Rule#
       * @member {string} selector The rule’s full selector represented
       *                           as a string.
       *
       * @example
       * const root = postcss.parse('a, b { }')
       * const rule = root.first
       * rule.selector //=> 'a, b'
       */

      /**
       * @memberof Rule#
       * @member {object} raws Information to generate byte-to-byte equal
       *                       node string as it was in the origin input.
       *
       * Every parser saves its own properties,
       * but the default CSS parser uses:
       *
       * * `before`: the space symbols before the node. It also stores `*`
       *   and `_` symbols before the declaration (IE hack).
       * * `after`: the space symbols after the last child of the node
       *   to the end of the node.
       * * `between`: the symbols between the property and value
       *   for declarations, selector and `{` for rules, or last parameter
       *   and `{` for at-rules.
       * * `semicolon`: contains `true` if the last child has
       *   an (optional) semicolon.
       * * `ownSemicolon`: contains `true` if there is semicolon after rule.
       *
       * PostCSS cleans selectors from comments and extra spaces,
       * but it stores origin content in raws properties.
       * As such, if you don’t change a declaration’s value,
       * PostCSS will use the raw value with comments.
       *
       * @example
       * const root = postcss.parse('a {\n  color:black\n}')
       * root.first.first.raws //=> { before: '', between: ' ', after: '\n' }
       */

    }]);

    return Rule;
  }(_container.default);

  var _default = Rule;
  exports.default = _default;
  module.exports = exports.default;

  });

  var container = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _declaration = _interopRequireDefault(declaration);

  var _comment = _interopRequireDefault(comment);

  var _node = _interopRequireDefault(node);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

  function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

  function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

  function cleanSource(nodes) {
    return nodes.map(function (i) {
      if (i.nodes) i.nodes = cleanSource(i.nodes);
      delete i.source;
      return i;
    });
  }
  /**
   * The {@link Root}, {@link AtRule}, and {@link Rule} container nodes
   * inherit some common methods to help work with their children.
   *
   * Note that all containers can store any content. If you write a rule inside
   * a rule, PostCSS will parse it.
   *
   * @extends Node
   * @abstract
   */


  var Container =
  /*#__PURE__*/
  function (_Node) {
    _inheritsLoose(Container, _Node);

    function Container() {
      return _Node.apply(this, arguments) || this;
    }

    var _proto = Container.prototype;

    _proto.push = function push(child) {
      child.parent = this;
      this.nodes.push(child);
      return this;
    }
    /**
     * Iterates through the container’s immediate children,
     * calling `callback` for each child.
     *
     * Returning `false` in the callback will break iteration.
     *
     * This method only iterates through the container’s immediate children.
     * If you need to recursively iterate through all the container’s descendant
     * nodes, use {@link Container#walk}.
     *
     * Unlike the for `{}`-cycle or `Array#forEach` this iterator is safe
     * if you are mutating the array of child nodes during iteration.
     * PostCSS will adjust the current index to match the mutations.
     *
     * @param {childIterator} callback Iterator receives each node and index.
     *
     * @return {false|undefined} Returns `false` if iteration was broke.
     *
     * @example
     * const root = postcss.parse('a { color: black; z-index: 1 }')
     * const rule = root.first
     *
     * for (const decl of rule.nodes) {
     *   decl.cloneBefore({ prop: '-webkit-' + decl.prop })
     *   // Cycle will be infinite, because cloneBefore moves the current node
     *   // to the next index
     * }
     *
     * rule.each(decl => {
     *   decl.cloneBefore({ prop: '-webkit-' + decl.prop })
     *   // Will be executed only for color and z-index
     * })
     */
    ;

    _proto.each = function each(callback) {
      if (!this.lastEach) this.lastEach = 0;
      if (!this.indexes) this.indexes = {};
      this.lastEach += 1;
      var id = this.lastEach;
      this.indexes[id] = 0;
      if (!this.nodes) return undefined;
      var index, result;

      while (this.indexes[id] < this.nodes.length) {
        index = this.indexes[id];
        result = callback(this.nodes[index], index);
        if (result === false) break;
        this.indexes[id] += 1;
      }

      delete this.indexes[id];
      return result;
    }
    /**
     * Traverses the container’s descendant nodes, calling callback
     * for each node.
     *
     * Like container.each(), this method is safe to use
     * if you are mutating arrays during iteration.
     *
     * If you only need to iterate through the container’s immediate children,
     * use {@link Container#each}.
     *
     * @param {childIterator} callback Iterator receives each node and index.
     *
     * @return {false|undefined} Returns `false` if iteration was broke.
     *
     * @example
     * root.walk(node => {
     *   // Traverses all descendant nodes.
     * })
     */
    ;

    _proto.walk = function walk(callback) {
      return this.each(function (child, i) {
        var result;

        try {
          result = callback(child, i);
        } catch (e) {
          e.postcssNode = child;

          if (e.stack && child.source && /\n\s{4}at /.test(e.stack)) {
            var s = child.source;
            e.stack = e.stack.replace(/\n\s{4}at /, "$&" + s.input.from + ":" + s.start.line + ":" + s.start.column + "$&");
          }

          throw e;
        }

        if (result !== false && child.walk) {
          result = child.walk(callback);
        }

        return result;
      });
    }
    /**
     * Traverses the container’s descendant nodes, calling callback
     * for each declaration node.
     *
     * If you pass a filter, iteration will only happen over declarations
     * with matching properties.
     *
     * Like {@link Container#each}, this method is safe
     * to use if you are mutating arrays during iteration.
     *
     * @param {string|RegExp} [prop]   String or regular expression
     *                                 to filter declarations by property name.
     * @param {childIterator} callback Iterator receives each node and index.
     *
     * @return {false|undefined} Returns `false` if iteration was broke.
     *
     * @example
     * root.walkDecls(decl => {
     *   checkPropertySupport(decl.prop)
     * })
     *
     * root.walkDecls('border-radius', decl => {
     *   decl.remove()
     * })
     *
     * root.walkDecls(/^background/, decl => {
     *   decl.value = takeFirstColorFromGradient(decl.value)
     * })
     */
    ;

    _proto.walkDecls = function walkDecls(prop, callback) {
      if (!callback) {
        callback = prop;
        return this.walk(function (child, i) {
          if (child.type === 'decl') {
            return callback(child, i);
          }
        });
      }

      if (prop instanceof RegExp) {
        return this.walk(function (child, i) {
          if (child.type === 'decl' && prop.test(child.prop)) {
            return callback(child, i);
          }
        });
      }

      return this.walk(function (child, i) {
        if (child.type === 'decl' && child.prop === prop) {
          return callback(child, i);
        }
      });
    }
    /**
     * Traverses the container’s descendant nodes, calling callback
     * for each rule node.
     *
     * If you pass a filter, iteration will only happen over rules
     * with matching selectors.
     *
     * Like {@link Container#each}, this method is safe
     * to use if you are mutating arrays during iteration.
     *
     * @param {string|RegExp} [selector] String or regular expression
     *                                   to filter rules by selector.
     * @param {childIterator} callback   Iterator receives each node and index.
     *
     * @return {false|undefined} returns `false` if iteration was broke.
     *
     * @example
     * const selectors = []
     * root.walkRules(rule => {
     *   selectors.push(rule.selector)
     * })
     * console.log(`Your CSS uses ${ selectors.length } selectors`)
     */
    ;

    _proto.walkRules = function walkRules(selector, callback) {
      if (!callback) {
        callback = selector;
        return this.walk(function (child, i) {
          if (child.type === 'rule') {
            return callback(child, i);
          }
        });
      }

      if (selector instanceof RegExp) {
        return this.walk(function (child, i) {
          if (child.type === 'rule' && selector.test(child.selector)) {
            return callback(child, i);
          }
        });
      }

      return this.walk(function (child, i) {
        if (child.type === 'rule' && child.selector === selector) {
          return callback(child, i);
        }
      });
    }
    /**
     * Traverses the container’s descendant nodes, calling callback
     * for each at-rule node.
     *
     * If you pass a filter, iteration will only happen over at-rules
     * that have matching names.
     *
     * Like {@link Container#each}, this method is safe
     * to use if you are mutating arrays during iteration.
     *
     * @param {string|RegExp} [name]   String or regular expression
     *                                 to filter at-rules by name.
     * @param {childIterator} callback Iterator receives each node and index.
     *
     * @return {false|undefined} Returns `false` if iteration was broke.
     *
     * @example
     * root.walkAtRules(rule => {
     *   if (isOld(rule.name)) rule.remove()
     * })
     *
     * let first = false
     * root.walkAtRules('charset', rule => {
     *   if (!first) {
     *     first = true
     *   } else {
     *     rule.remove()
     *   }
     * })
     */
    ;

    _proto.walkAtRules = function walkAtRules(name, callback) {
      if (!callback) {
        callback = name;
        return this.walk(function (child, i) {
          if (child.type === 'atrule') {
            return callback(child, i);
          }
        });
      }

      if (name instanceof RegExp) {
        return this.walk(function (child, i) {
          if (child.type === 'atrule' && name.test(child.name)) {
            return callback(child, i);
          }
        });
      }

      return this.walk(function (child, i) {
        if (child.type === 'atrule' && child.name === name) {
          return callback(child, i);
        }
      });
    }
    /**
     * Traverses the container’s descendant nodes, calling callback
     * for each comment node.
     *
     * Like {@link Container#each}, this method is safe
     * to use if you are mutating arrays during iteration.
     *
     * @param {childIterator} callback Iterator receives each node and index.
     *
     * @return {false|undefined} Returns `false` if iteration was broke.
     *
     * @example
     * root.walkComments(comment => {
     *   comment.remove()
     * })
     */
    ;

    _proto.walkComments = function walkComments(callback) {
      return this.walk(function (child, i) {
        if (child.type === 'comment') {
          return callback(child, i);
        }
      });
    }
    /**
     * Inserts new nodes to the end of the container.
     *
     * @param {...(Node|object|string|Node[])} children New nodes.
     *
     * @return {Node} This node for methods chain.
     *
     * @example
     * const decl1 = postcss.decl({ prop: 'color', value: 'black' })
     * const decl2 = postcss.decl({ prop: 'background-color', value: 'white' })
     * rule.append(decl1, decl2)
     *
     * root.append({ name: 'charset', params: '"UTF-8"' })  // at-rule
     * root.append({ selector: 'a' })                       // rule
     * rule.append({ prop: 'color', value: 'black' })       // declaration
     * rule.append({ text: 'Comment' })                     // comment
     *
     * root.append('a {}')
     * root.first.append('color: black; z-index: 1')
     */
    ;

    _proto.append = function append() {
      for (var _len = arguments.length, children = new Array(_len), _key = 0; _key < _len; _key++) {
        children[_key] = arguments[_key];
      }

      for (var _i = 0, _children = children; _i < _children.length; _i++) {
        var child = _children[_i];
        var nodes = this.normalize(child, this.last);

        for (var _iterator = nodes, _isArray = Array.isArray(_iterator), _i2 = 0, _iterator = _isArray ? _iterator : _iterator[Symbol.iterator]();;) {
          var _ref;

          if (_isArray) {
            if (_i2 >= _iterator.length) break;
            _ref = _iterator[_i2++];
          } else {
            _i2 = _iterator.next();
            if (_i2.done) break;
            _ref = _i2.value;
          }

          var node = _ref;
          this.nodes.push(node);
        }
      }

      return this;
    }
    /**
     * Inserts new nodes to the start of the container.
     *
     * @param {...(Node|object|string|Node[])} children New nodes.
     *
     * @return {Node} This node for methods chain.
     *
     * @example
     * const decl1 = postcss.decl({ prop: 'color', value: 'black' })
     * const decl2 = postcss.decl({ prop: 'background-color', value: 'white' })
     * rule.prepend(decl1, decl2)
     *
     * root.append({ name: 'charset', params: '"UTF-8"' })  // at-rule
     * root.append({ selector: 'a' })                       // rule
     * rule.append({ prop: 'color', value: 'black' })       // declaration
     * rule.append({ text: 'Comment' })                     // comment
     *
     * root.append('a {}')
     * root.first.append('color: black; z-index: 1')
     */
    ;

    _proto.prepend = function prepend() {
      for (var _len2 = arguments.length, children = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
        children[_key2] = arguments[_key2];
      }

      children = children.reverse();

      for (var _iterator2 = children, _isArray2 = Array.isArray(_iterator2), _i3 = 0, _iterator2 = _isArray2 ? _iterator2 : _iterator2[Symbol.iterator]();;) {
        var _ref2;

        if (_isArray2) {
          if (_i3 >= _iterator2.length) break;
          _ref2 = _iterator2[_i3++];
        } else {
          _i3 = _iterator2.next();
          if (_i3.done) break;
          _ref2 = _i3.value;
        }

        var child = _ref2;
        var nodes = this.normalize(child, this.first, 'prepend').reverse();

        for (var _iterator3 = nodes, _isArray3 = Array.isArray(_iterator3), _i4 = 0, _iterator3 = _isArray3 ? _iterator3 : _iterator3[Symbol.iterator]();;) {
          var _ref3;

          if (_isArray3) {
            if (_i4 >= _iterator3.length) break;
            _ref3 = _iterator3[_i4++];
          } else {
            _i4 = _iterator3.next();
            if (_i4.done) break;
            _ref3 = _i4.value;
          }

          var node = _ref3;
          this.nodes.unshift(node);
        }

        for (var id in this.indexes) {
          this.indexes[id] = this.indexes[id] + nodes.length;
        }
      }

      return this;
    };

    _proto.cleanRaws = function cleanRaws(keepBetween) {
      _Node.prototype.cleanRaws.call(this, keepBetween);

      if (this.nodes) {
        for (var _iterator4 = this.nodes, _isArray4 = Array.isArray(_iterator4), _i5 = 0, _iterator4 = _isArray4 ? _iterator4 : _iterator4[Symbol.iterator]();;) {
          var _ref4;

          if (_isArray4) {
            if (_i5 >= _iterator4.length) break;
            _ref4 = _iterator4[_i5++];
          } else {
            _i5 = _iterator4.next();
            if (_i5.done) break;
            _ref4 = _i5.value;
          }

          var node = _ref4;
          node.cleanRaws(keepBetween);
        }
      }
    }
    /**
     * Insert new node before old node within the container.
     *
     * @param {Node|number} exist             Child or child’s index.
     * @param {Node|object|string|Node[]} add New node.
     *
     * @return {Node} This node for methods chain.
     *
     * @example
     * rule.insertBefore(decl, decl.clone({ prop: '-webkit-' + decl.prop }))
     */
    ;

    _proto.insertBefore = function insertBefore(exist, add) {
      exist = this.index(exist);
      var type = exist === 0 ? 'prepend' : false;
      var nodes = this.normalize(add, this.nodes[exist], type).reverse();

      for (var _iterator5 = nodes, _isArray5 = Array.isArray(_iterator5), _i6 = 0, _iterator5 = _isArray5 ? _iterator5 : _iterator5[Symbol.iterator]();;) {
        var _ref5;

        if (_isArray5) {
          if (_i6 >= _iterator5.length) break;
          _ref5 = _iterator5[_i6++];
        } else {
          _i6 = _iterator5.next();
          if (_i6.done) break;
          _ref5 = _i6.value;
        }

        var node = _ref5;
        this.nodes.splice(exist, 0, node);
      }

      var index;

      for (var id in this.indexes) {
        index = this.indexes[id];

        if (exist <= index) {
          this.indexes[id] = index + nodes.length;
        }
      }

      return this;
    }
    /**
     * Insert new node after old node within the container.
     *
     * @param {Node|number} exist             Child or child’s index.
     * @param {Node|object|string|Node[]} add New node.
     *
     * @return {Node} This node for methods chain.
     */
    ;

    _proto.insertAfter = function insertAfter(exist, add) {
      exist = this.index(exist);
      var nodes = this.normalize(add, this.nodes[exist]).reverse();

      for (var _iterator6 = nodes, _isArray6 = Array.isArray(_iterator6), _i7 = 0, _iterator6 = _isArray6 ? _iterator6 : _iterator6[Symbol.iterator]();;) {
        var _ref6;

        if (_isArray6) {
          if (_i7 >= _iterator6.length) break;
          _ref6 = _iterator6[_i7++];
        } else {
          _i7 = _iterator6.next();
          if (_i7.done) break;
          _ref6 = _i7.value;
        }

        var node = _ref6;
        this.nodes.splice(exist + 1, 0, node);
      }

      var index;

      for (var id in this.indexes) {
        index = this.indexes[id];

        if (exist < index) {
          this.indexes[id] = index + nodes.length;
        }
      }

      return this;
    }
    /**
     * Removes node from the container and cleans the parent properties
     * from the node and its children.
     *
     * @param {Node|number} child Child or child’s index.
     *
     * @return {Node} This node for methods chain
     *
     * @example
     * rule.nodes.length  //=> 5
     * rule.removeChild(decl)
     * rule.nodes.length  //=> 4
     * decl.parent        //=> undefined
     */
    ;

    _proto.removeChild = function removeChild(child) {
      child = this.index(child);
      this.nodes[child].parent = undefined;
      this.nodes.splice(child, 1);
      var index;

      for (var id in this.indexes) {
        index = this.indexes[id];

        if (index >= child) {
          this.indexes[id] = index - 1;
        }
      }

      return this;
    }
    /**
     * Removes all children from the container
     * and cleans their parent properties.
     *
     * @return {Node} This node for methods chain.
     *
     * @example
     * rule.removeAll()
     * rule.nodes.length //=> 0
     */
    ;

    _proto.removeAll = function removeAll() {
      for (var _iterator7 = this.nodes, _isArray7 = Array.isArray(_iterator7), _i8 = 0, _iterator7 = _isArray7 ? _iterator7 : _iterator7[Symbol.iterator]();;) {
        var _ref7;

        if (_isArray7) {
          if (_i8 >= _iterator7.length) break;
          _ref7 = _iterator7[_i8++];
        } else {
          _i8 = _iterator7.next();
          if (_i8.done) break;
          _ref7 = _i8.value;
        }

        var node = _ref7;
        node.parent = undefined;
      }

      this.nodes = [];
      return this;
    }
    /**
     * Passes all declaration values within the container that match pattern
     * through callback, replacing those values with the returned result
     * of callback.
     *
     * This method is useful if you are using a custom unit or function
     * and need to iterate through all values.
     *
     * @param {string|RegExp} pattern      Replace pattern.
     * @param {object} opts                Options to speed up the search.
     * @param {string|string[]} opts.props An array of property names.
     * @param {string} opts.fast           String that’s used to narrow down
     *                                     values and speed up the regexp search.
     * @param {function|string} callback   String to replace pattern or callback
     *                                     that returns a new value. The callback
     *                                     will receive the same arguments
     *                                     as those passed to a function parameter
     *                                     of `String#replace`.
     *
     * @return {Node} This node for methods chain.
     *
     * @example
     * root.replaceValues(/\d+rem/, { fast: 'rem' }, string => {
     *   return 15 * parseInt(string) + 'px'
     * })
     */
    ;

    _proto.replaceValues = function replaceValues(pattern, opts, callback) {
      if (!callback) {
        callback = opts;
        opts = {};
      }

      this.walkDecls(function (decl) {
        if (opts.props && opts.props.indexOf(decl.prop) === -1) return;
        if (opts.fast && decl.value.indexOf(opts.fast) === -1) return;
        decl.value = decl.value.replace(pattern, callback);
      });
      return this;
    }
    /**
     * Returns `true` if callback returns `true`
     * for all of the container’s children.
     *
     * @param {childCondition} condition Iterator returns true or false.
     *
     * @return {boolean} Is every child pass condition.
     *
     * @example
     * const noPrefixes = rule.every(i => i.prop[0] !== '-')
     */
    ;

    _proto.every = function every(condition) {
      return this.nodes.every(condition);
    }
    /**
     * Returns `true` if callback returns `true` for (at least) one
     * of the container’s children.
     *
     * @param {childCondition} condition Iterator returns true or false.
     *
     * @return {boolean} Is some child pass condition.
     *
     * @example
     * const hasPrefix = rule.some(i => i.prop[0] === '-')
     */
    ;

    _proto.some = function some(condition) {
      return this.nodes.some(condition);
    }
    /**
     * Returns a `child`’s index within the {@link Container#nodes} array.
     *
     * @param {Node} child Child of the current container.
     *
     * @return {number} Child index.
     *
     * @example
     * rule.index( rule.nodes[2] ) //=> 2
     */
    ;

    _proto.index = function index(child) {
      if (typeof child === 'number') {
        return child;
      }

      return this.nodes.indexOf(child);
    }
    /**
     * The container’s first child.
     *
     * @type {Node}
     *
     * @example
     * rule.first === rules.nodes[0]
     */
    ;

    _proto.normalize = function normalize(nodes, sample) {
      var _this = this;

      if (typeof nodes === 'string') {
        var parse = parse_1;

        nodes = cleanSource(parse(nodes).nodes);
      } else if (Array.isArray(nodes)) {
        nodes = nodes.slice(0);

        for (var _iterator8 = nodes, _isArray8 = Array.isArray(_iterator8), _i9 = 0, _iterator8 = _isArray8 ? _iterator8 : _iterator8[Symbol.iterator]();;) {
          var _ref8;

          if (_isArray8) {
            if (_i9 >= _iterator8.length) break;
            _ref8 = _iterator8[_i9++];
          } else {
            _i9 = _iterator8.next();
            if (_i9.done) break;
            _ref8 = _i9.value;
          }

          var i = _ref8;
          if (i.parent) i.parent.removeChild(i, 'ignore');
        }
      } else if (nodes.type === 'root') {
        nodes = nodes.nodes.slice(0);

        for (var _iterator9 = nodes, _isArray9 = Array.isArray(_iterator9), _i10 = 0, _iterator9 = _isArray9 ? _iterator9 : _iterator9[Symbol.iterator]();;) {
          var _ref9;

          if (_isArray9) {
            if (_i10 >= _iterator9.length) break;
            _ref9 = _iterator9[_i10++];
          } else {
            _i10 = _iterator9.next();
            if (_i10.done) break;
            _ref9 = _i10.value;
          }

          var _i11 = _ref9;
          if (_i11.parent) _i11.parent.removeChild(_i11, 'ignore');
        }
      } else if (nodes.type) {
        nodes = [nodes];
      } else if (nodes.prop) {
        if (typeof nodes.value === 'undefined') {
          throw new Error('Value field is missed in node creation');
        } else if (typeof nodes.value !== 'string') {
          nodes.value = String(nodes.value);
        }

        nodes = [new _declaration.default(nodes)];
      } else if (nodes.selector) {
        var Rule = rule;

        nodes = [new Rule(nodes)];
      } else if (nodes.name) {
        var AtRule = atRule;

        nodes = [new AtRule(nodes)];
      } else if (nodes.text) {
        nodes = [new _comment.default(nodes)];
      } else {
        throw new Error('Unknown node type in node creation');
      }

      var processed = nodes.map(function (i) {
        if (i.parent) i.parent.removeChild(i);

        if (typeof i.raws.before === 'undefined') {
          if (sample && typeof sample.raws.before !== 'undefined') {
            i.raws.before = sample.raws.before.replace(/[^\s]/g, '');
          }
        }

        i.parent = _this;
        return i;
      });
      return processed;
    }
    /**
     * @memberof Container#
     * @member {Node[]} nodes An array containing the container’s children.
     *
     * @example
     * const root = postcss.parse('a { color: black }')
     * root.nodes.length           //=> 1
     * root.nodes[0].selector      //=> 'a'
     * root.nodes[0].nodes[0].prop //=> 'color'
     */
    ;

    _createClass(Container, [{
      key: "first",
      get: function get() {
        if (!this.nodes) return undefined;
        return this.nodes[0];
      }
      /**
       * The container’s last child.
       *
       * @type {Node}
       *
       * @example
       * rule.last === rule.nodes[rule.nodes.length - 1]
       */

    }, {
      key: "last",
      get: function get() {
        if (!this.nodes) return undefined;
        return this.nodes[this.nodes.length - 1];
      }
    }]);

    return Container;
  }(_node.default);

  var _default = Container;
  /**
   * @callback childCondition
   * @param {Node} node    Container child.
   * @param {number} index Child index.
   * @param {Node[]} nodes All container children.
   * @return {boolean}
   */

  /**
   * @callback childIterator
   * @param {Node} node    Container child.
   * @param {number} index Child index.
   * @return {false|undefined} Returning `false` will break iteration.
   */

  exports.default = _default;
  module.exports = exports.default;

  });

  var atRule = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _container = _interopRequireDefault(container);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

  /**
   * Represents an at-rule.
   *
   * If it’s followed in the CSS by a {} block, this node will have
   * a nodes property representing its children.
   *
   * @extends Container
   *
   * @example
   * const root = postcss.parse('@charset "UTF-8"; @media print {}')
   *
   * const charset = root.first
   * charset.type  //=> 'atrule'
   * charset.nodes //=> undefined
   *
   * const media = root.last
   * media.nodes   //=> []
   */
  var AtRule =
  /*#__PURE__*/
  function (_Container) {
    _inheritsLoose(AtRule, _Container);

    function AtRule(defaults) {
      var _this;

      _this = _Container.call(this, defaults) || this;
      _this.type = 'atrule';
      return _this;
    }

    var _proto = AtRule.prototype;

    _proto.append = function append() {
      var _Container$prototype$;

      if (!this.nodes) this.nodes = [];

      for (var _len = arguments.length, children = new Array(_len), _key = 0; _key < _len; _key++) {
        children[_key] = arguments[_key];
      }

      return (_Container$prototype$ = _Container.prototype.append).call.apply(_Container$prototype$, [this].concat(children));
    };

    _proto.prepend = function prepend() {
      var _Container$prototype$2;

      if (!this.nodes) this.nodes = [];

      for (var _len2 = arguments.length, children = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
        children[_key2] = arguments[_key2];
      }

      return (_Container$prototype$2 = _Container.prototype.prepend).call.apply(_Container$prototype$2, [this].concat(children));
    }
    /**
     * @memberof AtRule#
     * @member {string} name The at-rule’s name immediately follows the `@`.
     *
     * @example
     * const root  = postcss.parse('@media print {}')
     * media.name //=> 'media'
     * const media = root.first
     */

    /**
     * @memberof AtRule#
     * @member {string} params The at-rule’s parameters, the values
     *                         that follow the at-rule’s name but precede
     *                         any {} block.
     *
     * @example
     * const root  = postcss.parse('@media print, screen {}')
     * const media = root.first
     * media.params //=> 'print, screen'
     */

    /**
     * @memberof AtRule#
     * @member {object} raws Information to generate byte-to-byte equal
     *                        node string as it was in the origin input.
     *
     * Every parser saves its own properties,
     * but the default CSS parser uses:
     *
     * * `before`: the space symbols before the node. It also stores `*`
     *   and `_` symbols before the declaration (IE hack).
     * * `after`: the space symbols after the last child of the node
     *   to the end of the node.
     * * `between`: the symbols between the property and value
     *   for declarations, selector and `{` for rules, or last parameter
     *   and `{` for at-rules.
     * * `semicolon`: contains true if the last child has
     *   an (optional) semicolon.
     * * `afterName`: the space between the at-rule name and its parameters.
     *
     * PostCSS cleans at-rule parameters from comments and extra spaces,
     * but it stores origin content in raws properties.
     * As such, if you don’t change a declaration’s value,
     * PostCSS will use the raw value with comments.
     *
     * @example
     * const root = postcss.parse('  @media\nprint {\n}')
     * root.first.first.raws //=> { before: '  ',
     *                       //     between: ' ',
     *                       //     afterName: '\n',
     *                       //     after: '\n' }
     */
    ;

    return AtRule;
  }(_container.default);

  var _default = AtRule;
  exports.default = _default;
  module.exports = exports.default;

  });

  var root = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _container = _interopRequireDefault(container);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

  /**
   * Represents a CSS file and contains all its parsed nodes.
   *
   * @extends Container
   *
   * @example
   * const root = postcss.parse('a{color:black} b{z-index:2}')
   * root.type         //=> 'root'
   * root.nodes.length //=> 2
   */
  var Root =
  /*#__PURE__*/
  function (_Container) {
    _inheritsLoose(Root, _Container);

    function Root(defaults) {
      var _this;

      _this = _Container.call(this, defaults) || this;
      _this.type = 'root';
      if (!_this.nodes) _this.nodes = [];
      return _this;
    }

    var _proto = Root.prototype;

    _proto.removeChild = function removeChild(child, ignore) {
      var index = this.index(child);

      if (!ignore && index === 0 && this.nodes.length > 1) {
        this.nodes[1].raws.before = this.nodes[index].raws.before;
      }

      return _Container.prototype.removeChild.call(this, child);
    };

    _proto.normalize = function normalize(child, sample, type) {
      var nodes = _Container.prototype.normalize.call(this, child);

      if (sample) {
        if (type === 'prepend') {
          if (this.nodes.length > 1) {
            sample.raws.before = this.nodes[1].raws.before;
          } else {
            delete sample.raws.before;
          }
        } else if (this.first !== sample) {
          for (var _iterator = nodes, _isArray = Array.isArray(_iterator), _i = 0, _iterator = _isArray ? _iterator : _iterator[Symbol.iterator]();;) {
            var _ref;

            if (_isArray) {
              if (_i >= _iterator.length) break;
              _ref = _iterator[_i++];
            } else {
              _i = _iterator.next();
              if (_i.done) break;
              _ref = _i.value;
            }

            var node = _ref;
            node.raws.before = sample.raws.before;
          }
        }
      }

      return nodes;
    }
    /**
     * Returns a {@link Result} instance representing the root’s CSS.
     *
     * @param {processOptions} [opts] Options with only `to` and `map` keys.
     *
     * @return {Result} Result with current root’s CSS.
     *
     * @example
     * const root1 = postcss.parse(css1, { from: 'a.css' })
     * const root2 = postcss.parse(css2, { from: 'b.css' })
     * root1.append(root2)
     * const result = root1.toResult({ to: 'all.css', map: true })
     */
    ;

    _proto.toResult = function toResult(opts) {
      if (opts === void 0) {
        opts = {};
      }

      var LazyResult = lazyResult;

      var Processor = processor;

      var lazy = new LazyResult(new Processor(), this, opts);
      return lazy.stringify();
    }
    /**
     * @memberof Root#
     * @member {object} raws Information to generate byte-to-byte equal
     *                       node string as it was in the origin input.
     *
     * Every parser saves its own properties,
     * but the default CSS parser uses:
     *
     * * `after`: the space symbols after the last child to the end of file.
     * * `semicolon`: is the last child has an (optional) semicolon.
     *
     * @example
     * postcss.parse('a {}\n').raws //=> { after: '\n' }
     * postcss.parse('a {}').raws   //=> { after: '' }
     */
    ;

    return Root;
  }(_container.default);

  var _default = Root;
  exports.default = _default;
  module.exports = exports.default;

  });

  var parser = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _declaration = _interopRequireDefault(declaration);

  var _tokenize = _interopRequireDefault(tokenize);

  var _comment = _interopRequireDefault(comment);

  var _atRule = _interopRequireDefault(atRule);

  var _root = _interopRequireDefault(root);

  var _rule = _interopRequireDefault(rule);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  var Parser =
  /*#__PURE__*/
  function () {
    function Parser(input) {
      this.input = input;
      this.root = new _root.default();
      this.current = this.root;
      this.spaces = '';
      this.semicolon = false;
      this.createTokenizer();
      this.root.source = {
        input: input,
        start: {
          line: 1,
          column: 1
        }
      };
    }

    var _proto = Parser.prototype;

    _proto.createTokenizer = function createTokenizer() {
      this.tokenizer = (0, _tokenize.default)(this.input);
    };

    _proto.parse = function parse() {
      var token;

      while (!this.tokenizer.endOfFile()) {
        token = this.tokenizer.nextToken();

        switch (token[0]) {
          case 'space':
            this.spaces += token[1];
            break;

          case ';':
            this.freeSemicolon(token);
            break;

          case '}':
            this.end(token);
            break;

          case 'comment':
            this.comment(token);
            break;

          case 'at-word':
            this.atrule(token);
            break;

          case '{':
            this.emptyRule(token);
            break;

          default:
            this.other(token);
            break;
        }
      }

      this.endFile();
    };

    _proto.comment = function comment(token) {
      var node = new _comment.default();
      this.init(node, token[2], token[3]);
      node.source.end = {
        line: token[4],
        column: token[5]
      };
      var text = token[1].slice(2, -2);

      if (/^\s*$/.test(text)) {
        node.text = '';
        node.raws.left = text;
        node.raws.right = '';
      } else {
        var match = text.match(/^(\s*)([^]*[^\s])(\s*)$/);
        node.text = match[2];
        node.raws.left = match[1];
        node.raws.right = match[3];
      }
    };

    _proto.emptyRule = function emptyRule(token) {
      var node = new _rule.default();
      this.init(node, token[2], token[3]);
      node.selector = '';
      node.raws.between = '';
      this.current = node;
    };

    _proto.other = function other(start) {
      var end = false;
      var type = null;
      var colon = false;
      var bracket = null;
      var brackets = [];
      var tokens = [];
      var token = start;

      while (token) {
        type = token[0];
        tokens.push(token);

        if (type === '(' || type === '[') {
          if (!bracket) bracket = token;
          brackets.push(type === '(' ? ')' : ']');
        } else if (brackets.length === 0) {
          if (type === ';') {
            if (colon) {
              this.decl(tokens);
              return;
            } else {
              break;
            }
          } else if (type === '{') {
            this.rule(tokens);
            return;
          } else if (type === '}') {
            this.tokenizer.back(tokens.pop());
            end = true;
            break;
          } else if (type === ':') {
            colon = true;
          }
        } else if (type === brackets[brackets.length - 1]) {
          brackets.pop();
          if (brackets.length === 0) bracket = null;
        }

        token = this.tokenizer.nextToken();
      }

      if (this.tokenizer.endOfFile()) end = true;
      if (brackets.length > 0) this.unclosedBracket(bracket);

      if (end && colon) {
        while (tokens.length) {
          token = tokens[tokens.length - 1][0];
          if (token !== 'space' && token !== 'comment') break;
          this.tokenizer.back(tokens.pop());
        }

        this.decl(tokens);
      } else {
        this.unknownWord(tokens);
      }
    };

    _proto.rule = function rule(tokens) {
      tokens.pop();
      var node = new _rule.default();
      this.init(node, tokens[0][2], tokens[0][3]);
      node.raws.between = this.spacesAndCommentsFromEnd(tokens);
      this.raw(node, 'selector', tokens);
      this.current = node;
    };

    _proto.decl = function decl(tokens) {
      var node = new _declaration.default();
      this.init(node);
      var last = tokens[tokens.length - 1];

      if (last[0] === ';') {
        this.semicolon = true;
        tokens.pop();
      }

      if (last[4]) {
        node.source.end = {
          line: last[4],
          column: last[5]
        };
      } else {
        node.source.end = {
          line: last[2],
          column: last[3]
        };
      }

      while (tokens[0][0] !== 'word') {
        if (tokens.length === 1) this.unknownWord(tokens);
        node.raws.before += tokens.shift()[1];
      }

      node.source.start = {
        line: tokens[0][2],
        column: tokens[0][3]
      };
      node.prop = '';

      while (tokens.length) {
        var type = tokens[0][0];

        if (type === ':' || type === 'space' || type === 'comment') {
          break;
        }

        node.prop += tokens.shift()[1];
      }

      node.raws.between = '';
      var token;

      while (tokens.length) {
        token = tokens.shift();

        if (token[0] === ':') {
          node.raws.between += token[1];
          break;
        } else {
          if (token[0] === 'word' && /\w/.test(token[1])) {
            this.unknownWord([token]);
          }

          node.raws.between += token[1];
        }
      }

      if (node.prop[0] === '_' || node.prop[0] === '*') {
        node.raws.before += node.prop[0];
        node.prop = node.prop.slice(1);
      }

      node.raws.between += this.spacesAndCommentsFromStart(tokens);
      this.precheckMissedSemicolon(tokens);

      for (var i = tokens.length - 1; i > 0; i--) {
        token = tokens[i];

        if (token[1].toLowerCase() === '!important') {
          node.important = true;
          var string = this.stringFrom(tokens, i);
          string = this.spacesFromEnd(tokens) + string;
          if (string !== ' !important') node.raws.important = string;
          break;
        } else if (token[1].toLowerCase() === 'important') {
          var cache = tokens.slice(0);
          var str = '';

          for (var j = i; j > 0; j--) {
            var _type = cache[j][0];

            if (str.trim().indexOf('!') === 0 && _type !== 'space') {
              break;
            }

            str = cache.pop()[1] + str;
          }

          if (str.trim().indexOf('!') === 0) {
            node.important = true;
            node.raws.important = str;
            tokens = cache;
          }
        }

        if (token[0] !== 'space' && token[0] !== 'comment') {
          break;
        }
      }

      this.raw(node, 'value', tokens);
      if (node.value.indexOf(':') !== -1) this.checkMissedSemicolon(tokens);
    };

    _proto.atrule = function atrule(token) {
      var node = new _atRule.default();
      node.name = token[1].slice(1);

      if (node.name === '') {
        this.unnamedAtrule(node, token);
      }

      this.init(node, token[2], token[3]);
      var prev;
      var shift;
      var last = false;
      var open = false;
      var params = [];

      while (!this.tokenizer.endOfFile()) {
        token = this.tokenizer.nextToken();

        if (token[0] === ';') {
          node.source.end = {
            line: token[2],
            column: token[3]
          };
          this.semicolon = true;
          break;
        } else if (token[0] === '{') {
          open = true;
          break;
        } else if (token[0] === '}') {
          if (params.length > 0) {
            shift = params.length - 1;
            prev = params[shift];

            while (prev && prev[0] === 'space') {
              prev = params[--shift];
            }

            if (prev) {
              node.source.end = {
                line: prev[4],
                column: prev[5]
              };
            }
          }

          this.end(token);
          break;
        } else {
          params.push(token);
        }

        if (this.tokenizer.endOfFile()) {
          last = true;
          break;
        }
      }

      node.raws.between = this.spacesAndCommentsFromEnd(params);

      if (params.length) {
        node.raws.afterName = this.spacesAndCommentsFromStart(params);
        this.raw(node, 'params', params);

        if (last) {
          token = params[params.length - 1];
          node.source.end = {
            line: token[4],
            column: token[5]
          };
          this.spaces = node.raws.between;
          node.raws.between = '';
        }
      } else {
        node.raws.afterName = '';
        node.params = '';
      }

      if (open) {
        node.nodes = [];
        this.current = node;
      }
    };

    _proto.end = function end(token) {
      if (this.current.nodes && this.current.nodes.length) {
        this.current.raws.semicolon = this.semicolon;
      }

      this.semicolon = false;
      this.current.raws.after = (this.current.raws.after || '') + this.spaces;
      this.spaces = '';

      if (this.current.parent) {
        this.current.source.end = {
          line: token[2],
          column: token[3]
        };
        this.current = this.current.parent;
      } else {
        this.unexpectedClose(token);
      }
    };

    _proto.endFile = function endFile() {
      if (this.current.parent) this.unclosedBlock();

      if (this.current.nodes && this.current.nodes.length) {
        this.current.raws.semicolon = this.semicolon;
      }

      this.current.raws.after = (this.current.raws.after || '') + this.spaces;
    };

    _proto.freeSemicolon = function freeSemicolon(token) {
      this.spaces += token[1];

      if (this.current.nodes) {
        var prev = this.current.nodes[this.current.nodes.length - 1];

        if (prev && prev.type === 'rule' && !prev.raws.ownSemicolon) {
          prev.raws.ownSemicolon = this.spaces;
          this.spaces = '';
        }
      }
    } // Helpers
    ;

    _proto.init = function init(node, line, column) {
      this.current.push(node);
      node.source = {
        start: {
          line: line,
          column: column
        },
        input: this.input
      };
      node.raws.before = this.spaces;
      this.spaces = '';
      if (node.type !== 'comment') this.semicolon = false;
    };

    _proto.raw = function raw(node, prop, tokens) {
      var token, type;
      var length = tokens.length;
      var value = '';
      var clean = true;
      var next, prev;
      var pattern = /^([.|#])?([\w])+/i;

      for (var i = 0; i < length; i += 1) {
        token = tokens[i];
        type = token[0];

        if (type === 'comment' && node.type === 'rule') {
          prev = tokens[i - 1];
          next = tokens[i + 1];

          if (prev[0] !== 'space' && next[0] !== 'space' && pattern.test(prev[1]) && pattern.test(next[1])) {
            value += token[1];
          } else {
            clean = false;
          }

          continue;
        }

        if (type === 'comment' || type === 'space' && i === length - 1) {
          clean = false;
        } else {
          value += token[1];
        }
      }

      if (!clean) {
        var raw = tokens.reduce(function (all, i) {
          return all + i[1];
        }, '');
        node.raws[prop] = {
          value: value,
          raw: raw
        };
      }

      node[prop] = value;
    };

    _proto.spacesAndCommentsFromEnd = function spacesAndCommentsFromEnd(tokens) {
      var lastTokenType;
      var spaces = '';

      while (tokens.length) {
        lastTokenType = tokens[tokens.length - 1][0];
        if (lastTokenType !== 'space' && lastTokenType !== 'comment') break;
        spaces = tokens.pop()[1] + spaces;
      }

      return spaces;
    };

    _proto.spacesAndCommentsFromStart = function spacesAndCommentsFromStart(tokens) {
      var next;
      var spaces = '';

      while (tokens.length) {
        next = tokens[0][0];
        if (next !== 'space' && next !== 'comment') break;
        spaces += tokens.shift()[1];
      }

      return spaces;
    };

    _proto.spacesFromEnd = function spacesFromEnd(tokens) {
      var lastTokenType;
      var spaces = '';

      while (tokens.length) {
        lastTokenType = tokens[tokens.length - 1][0];
        if (lastTokenType !== 'space') break;
        spaces = tokens.pop()[1] + spaces;
      }

      return spaces;
    };

    _proto.stringFrom = function stringFrom(tokens, from) {
      var result = '';

      for (var i = from; i < tokens.length; i++) {
        result += tokens[i][1];
      }

      tokens.splice(from, tokens.length - from);
      return result;
    };

    _proto.colon = function colon(tokens) {
      var brackets = 0;
      var token, type, prev;

      for (var i = 0; i < tokens.length; i++) {
        token = tokens[i];
        type = token[0];

        if (type === '(') {
          brackets += 1;
        }

        if (type === ')') {
          brackets -= 1;
        }

        if (brackets === 0 && type === ':') {
          if (!prev) {
            this.doubleColon(token);
          } else if (prev[0] === 'word' && prev[1] === 'progid') {
            continue;
          } else {
            return i;
          }
        }

        prev = token;
      }

      return false;
    } // Errors
    ;

    _proto.unclosedBracket = function unclosedBracket(bracket) {
      throw this.input.error('Unclosed bracket', bracket[2], bracket[3]);
    };

    _proto.unknownWord = function unknownWord(tokens) {
      throw this.input.error('Unknown word', tokens[0][2], tokens[0][3]);
    };

    _proto.unexpectedClose = function unexpectedClose(token) {
      throw this.input.error('Unexpected }', token[2], token[3]);
    };

    _proto.unclosedBlock = function unclosedBlock() {
      var pos = this.current.source.start;
      throw this.input.error('Unclosed block', pos.line, pos.column);
    };

    _proto.doubleColon = function doubleColon(token) {
      throw this.input.error('Double colon', token[2], token[3]);
    };

    _proto.unnamedAtrule = function unnamedAtrule(node, token) {
      throw this.input.error('At-rule without name', token[2], token[3]);
    };

    _proto.precheckMissedSemicolon = function precheckMissedSemicolon()
    /* tokens */
    {// Hook for Safe Parser
    };

    _proto.checkMissedSemicolon = function checkMissedSemicolon(tokens) {
      var colon = this.colon(tokens);
      if (colon === false) return;
      var founded = 0;
      var token;

      for (var j = colon - 1; j >= 0; j--) {
        token = tokens[j];

        if (token[0] !== 'space') {
          founded += 1;
          if (founded === 2) break;
        }
      }

      throw this.input.error('Missed semicolon', token[2], token[3]);
    };

    return Parser;
  }();

  exports.default = Parser;
  module.exports = exports.default;

  });

  var parse_1 = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _parser = _interopRequireDefault(parser);

  var _input = _interopRequireDefault(input);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function parse(css, opts) {
    var input = new _input.default(css, opts);
    var parser = new _parser.default(input);

    try {
      parser.parse();
    } catch (e) {
      if (process.env.NODE_ENV !== 'production') {
        if (e.name === 'CssSyntaxError' && opts && opts.from) {
          if (/\.scss$/i.test(opts.from)) {
            e.message += '\nYou tried to parse SCSS with ' + 'the standard CSS parser; ' + 'try again with the postcss-scss parser';
          } else if (/\.sass/i.test(opts.from)) {
            e.message += '\nYou tried to parse Sass with ' + 'the standard CSS parser; ' + 'try again with the postcss-sass parser';
          } else if (/\.less$/i.test(opts.from)) {
            e.message += '\nYou tried to parse Less with ' + 'the standard CSS parser; ' + 'try again with the postcss-less parser';
          }
        }
      }

      throw e;
    }

    return parser.root;
  }

  var _default = parse;
  exports.default = _default;
  module.exports = exports.default;

  });

  var lazyResult = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _mapGenerator = _interopRequireDefault(mapGenerator);

  var _stringify2 = _interopRequireDefault(stringify_1);

  var _warnOnce = _interopRequireDefault(warnOnce_1);

  var _result = _interopRequireDefault(result);

  var _parse = _interopRequireDefault(parse_1);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

  function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

  function isPromise(obj) {
    return typeof obj === 'object' && typeof obj.then === 'function';
  }
  /**
   * A Promise proxy for the result of PostCSS transformations.
   *
   * A `LazyResult` instance is returned by {@link Processor#process}.
   *
   * @example
   * const lazy = postcss([autoprefixer]).process(css)
   */


  var LazyResult =
  /*#__PURE__*/
  function () {
    function LazyResult(processor, css, opts) {
      this.stringified = false;
      this.processed = false;
      var root;

      if (typeof css === 'object' && css !== null && css.type === 'root') {
        root = css;
      } else if (css instanceof LazyResult || css instanceof _result.default) {
        root = css.root;

        if (css.map) {
          if (typeof opts.map === 'undefined') opts.map = {};
          if (!opts.map.inline) opts.map.inline = false;
          opts.map.prev = css.map;
        }
      } else {
        var parser = _parse.default;
        if (opts.syntax) parser = opts.syntax.parse;
        if (opts.parser) parser = opts.parser;
        if (parser.parse) parser = parser.parse;

        try {
          root = parser(css, opts);
        } catch (error) {
          this.error = error;
        }
      }

      this.result = new _result.default(processor, root, opts);
    }
    /**
     * Returns a {@link Processor} instance, which will be used
     * for CSS transformations.
     *
     * @type {Processor}
     */


    var _proto = LazyResult.prototype;

    /**
     * Processes input CSS through synchronous plugins
     * and calls {@link Result#warnings()}.
     *
     * @return {Warning[]} Warnings from plugins.
     */
    _proto.warnings = function warnings() {
      return this.sync().warnings();
    }
    /**
     * Alias for the {@link LazyResult#css} property.
     *
     * @example
     * lazy + '' === lazy.css
     *
     * @return {string} Output CSS.
     */
    ;

    _proto.toString = function toString() {
      return this.css;
    }
    /**
     * Processes input CSS through synchronous and asynchronous plugins
     * and calls `onFulfilled` with a Result instance. If a plugin throws
     * an error, the `onRejected` callback will be executed.
     *
     * It implements standard Promise API.
     *
     * @param {onFulfilled} onFulfilled Callback will be executed
     *                                  when all plugins will finish work.
     * @param {onRejected}  onRejected  Callback will be executed on any error.
     *
     * @return {Promise} Promise API to make queue.
     *
     * @example
     * postcss([autoprefixer]).process(css, { from: cssPath }).then(result => {
     *   console.log(result.css)
     * })
     */
    ;

    _proto.then = function then(onFulfilled, onRejected) {
      if (process.env.NODE_ENV !== 'production') {
        if (!('from' in this.opts)) {
          (0, _warnOnce.default)('Without `from` option PostCSS could generate wrong source map ' + 'and will not find Browserslist config. Set it to CSS file path ' + 'or to `undefined` to prevent this warning.');
        }
      }

      return this.async().then(onFulfilled, onRejected);
    }
    /**
     * Processes input CSS through synchronous and asynchronous plugins
     * and calls onRejected for each error thrown in any plugin.
     *
     * It implements standard Promise API.
     *
     * @param {onRejected} onRejected Callback will be executed on any error.
     *
     * @return {Promise} Promise API to make queue.
     *
     * @example
     * postcss([autoprefixer]).process(css).then(result => {
     *   console.log(result.css)
     * }).catch(error => {
     *   console.error(error)
     * })
     */
    ;

    _proto.catch = function _catch(onRejected) {
      return this.async().catch(onRejected);
    }
    /**
     * Processes input CSS through synchronous and asynchronous plugins
     * and calls onFinally on any error or when all plugins will finish work.
     *
     * It implements standard Promise API.
     *
     * @param {onFinally} onFinally Callback will be executed on any error or
     *                              when all plugins will finish work.
     *
     * @return {Promise} Promise API to make queue.
     *
     * @example
     * postcss([autoprefixer]).process(css).finally(() => {
     *   console.log('processing ended')
     * })
     */
    ;

    _proto.finally = function _finally(onFinally) {
      return this.async().then(onFinally, onFinally);
    };

    _proto.handleError = function handleError(error, plugin) {
      try {
        this.error = error;

        if (error.name === 'CssSyntaxError' && !error.plugin) {
          error.plugin = plugin.postcssPlugin;
          error.setMessage();
        } else if (plugin.postcssVersion) {
          if (process.env.NODE_ENV !== 'production') {
            var pluginName = plugin.postcssPlugin;
            var pluginVer = plugin.postcssVersion;
            var runtimeVer = this.result.processor.version;
            var a = pluginVer.split('.');
            var b = runtimeVer.split('.');

            if (a[0] !== b[0] || parseInt(a[1]) > parseInt(b[1])) {
              console.error('Unknown error from PostCSS plugin. Your current PostCSS ' + 'version is ' + runtimeVer + ', but ' + pluginName + ' uses ' + pluginVer + '. Perhaps this is the source of the error below.');
            }
          }
        }
      } catch (err) {
        if (console && console.error) console.error(err);
      }
    };

    _proto.asyncTick = function asyncTick(resolve, reject) {
      var _this = this;

      if (this.plugin >= this.processor.plugins.length) {
        this.processed = true;
        return resolve();
      }

      try {
        var plugin = this.processor.plugins[this.plugin];
        var promise = this.run(plugin);
        this.plugin += 1;

        if (isPromise(promise)) {
          promise.then(function () {
            _this.asyncTick(resolve, reject);
          }).catch(function (error) {
            _this.handleError(error, plugin);

            _this.processed = true;
            reject(error);
          });
        } else {
          this.asyncTick(resolve, reject);
        }
      } catch (error) {
        this.processed = true;
        reject(error);
      }
    };

    _proto.async = function async() {
      var _this2 = this;

      if (this.processed) {
        return new Promise(function (resolve, reject) {
          if (_this2.error) {
            reject(_this2.error);
          } else {
            resolve(_this2.stringify());
          }
        });
      }

      if (this.processing) {
        return this.processing;
      }

      this.processing = new Promise(function (resolve, reject) {
        if (_this2.error) return reject(_this2.error);
        _this2.plugin = 0;

        _this2.asyncTick(resolve, reject);
      }).then(function () {
        _this2.processed = true;
        return _this2.stringify();
      });
      return this.processing;
    };

    _proto.sync = function sync() {
      if (this.processed) return this.result;
      this.processed = true;

      if (this.processing) {
        throw new Error('Use process(css).then(cb) to work with async plugins');
      }

      if (this.error) throw this.error;

      for (var _iterator = this.result.processor.plugins, _isArray = Array.isArray(_iterator), _i = 0, _iterator = _isArray ? _iterator : _iterator[Symbol.iterator]();;) {
        var _ref;

        if (_isArray) {
          if (_i >= _iterator.length) break;
          _ref = _iterator[_i++];
        } else {
          _i = _iterator.next();
          if (_i.done) break;
          _ref = _i.value;
        }

        var plugin = _ref;
        var promise = this.run(plugin);

        if (isPromise(promise)) {
          throw new Error('Use process(css).then(cb) to work with async plugins');
        }
      }

      return this.result;
    };

    _proto.run = function run(plugin) {
      this.result.lastPlugin = plugin;

      try {
        return plugin(this.result.root, this.result);
      } catch (error) {
        this.handleError(error, plugin);
        throw error;
      }
    };

    _proto.stringify = function stringify() {
      if (this.stringified) return this.result;
      this.stringified = true;
      this.sync();
      var opts = this.result.opts;
      var str = _stringify2.default;
      if (opts.syntax) str = opts.syntax.stringify;
      if (opts.stringifier) str = opts.stringifier;
      if (str.stringify) str = str.stringify;
      var map = new _mapGenerator.default(str, this.result.root, this.result.opts);
      var data = map.generate();
      this.result.css = data[0];
      this.result.map = data[1];
      return this.result;
    };

    _createClass(LazyResult, [{
      key: "processor",
      get: function get() {
        return this.result.processor;
      }
      /**
       * Options from the {@link Processor#process} call.
       *
       * @type {processOptions}
       */

    }, {
      key: "opts",
      get: function get() {
        return this.result.opts;
      }
      /**
       * Processes input CSS through synchronous plugins, converts `Root`
       * to a CSS string and returns {@link Result#css}.
       *
       * This property will only work with synchronous plugins.
       * If the processor contains any asynchronous plugins
       * it will throw an error. This is why this method is only
       * for debug purpose, you should always use {@link LazyResult#then}.
       *
       * @type {string}
       * @see Result#css
       */

    }, {
      key: "css",
      get: function get() {
        return this.stringify().css;
      }
      /**
       * An alias for the `css` property. Use it with syntaxes
       * that generate non-CSS output.
       *
       * This property will only work with synchronous plugins.
       * If the processor contains any asynchronous plugins
       * it will throw an error. This is why this method is only
       * for debug purpose, you should always use {@link LazyResult#then}.
       *
       * @type {string}
       * @see Result#content
       */

    }, {
      key: "content",
      get: function get() {
        return this.stringify().content;
      }
      /**
       * Processes input CSS through synchronous plugins
       * and returns {@link Result#map}.
       *
       * This property will only work with synchronous plugins.
       * If the processor contains any asynchronous plugins
       * it will throw an error. This is why this method is only
       * for debug purpose, you should always use {@link LazyResult#then}.
       *
       * @type {SourceMapGenerator}
       * @see Result#map
       */

    }, {
      key: "map",
      get: function get() {
        return this.stringify().map;
      }
      /**
       * Processes input CSS through synchronous plugins
       * and returns {@link Result#root}.
       *
       * This property will only work with synchronous plugins. If the processor
       * contains any asynchronous plugins it will throw an error.
       *
       * This is why this method is only for debug purpose,
       * you should always use {@link LazyResult#then}.
       *
       * @type {Root}
       * @see Result#root
       */

    }, {
      key: "root",
      get: function get() {
        return this.sync().root;
      }
      /**
       * Processes input CSS through synchronous plugins
       * and returns {@link Result#messages}.
       *
       * This property will only work with synchronous plugins. If the processor
       * contains any asynchronous plugins it will throw an error.
       *
       * This is why this method is only for debug purpose,
       * you should always use {@link LazyResult#then}.
       *
       * @type {Message[]}
       * @see Result#messages
       */

    }, {
      key: "messages",
      get: function get() {
        return this.sync().messages;
      }
    }]);

    return LazyResult;
  }();

  var _default = LazyResult;
  /**
   * @callback onFulfilled
   * @param {Result} result
   */

  /**
   * @callback onRejected
   * @param {Error} error
   */

  exports.default = _default;
  module.exports = exports.default;

  });

  var processor = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _lazyResult = _interopRequireDefault(lazyResult);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  /**
   * Contains plugins to process CSS. Create one `Processor` instance,
   * initialize its plugins, and then use that instance on numerous CSS files.
   *
   * @example
   * const processor = postcss([autoprefixer, precss])
   * processor.process(css1).then(result => console.log(result.css))
   * processor.process(css2).then(result => console.log(result.css))
   */
  var Processor =
  /*#__PURE__*/
  function () {
    /**
     * @param {Array.<Plugin|pluginFunction>|Processor} plugins PostCSS plugins.
     *        See {@link Processor#use} for plugin format.
     */
    function Processor(plugins) {
      if (plugins === void 0) {
        plugins = [];
      }

      /**
       * Current PostCSS version.
       *
       * @type {string}
       *
       * @example
       * if (result.processor.version.split('.')[0] !== '6') {
       *   throw new Error('This plugin works only with PostCSS 6')
       * }
       */
      this.version = '7.0.32';
      /**
       * Plugins added to this processor.
       *
       * @type {pluginFunction[]}
       *
       * @example
       * const processor = postcss([autoprefixer, precss])
       * processor.plugins.length //=> 2
       */

      this.plugins = this.normalize(plugins);
    }
    /**
     * Adds a plugin to be used as a CSS processor.
     *
     * PostCSS plugin can be in 4 formats:
     * * A plugin created by {@link postcss.plugin} method.
     * * A function. PostCSS will pass the function a @{link Root}
     *   as the first argument and current {@link Result} instance
     *   as the second.
     * * An object with a `postcss` method. PostCSS will use that method
     *   as described in #2.
     * * Another {@link Processor} instance. PostCSS will copy plugins
     *   from that instance into this one.
     *
     * Plugins can also be added by passing them as arguments when creating
     * a `postcss` instance (see [`postcss(plugins)`]).
     *
     * Asynchronous plugins should return a `Promise` instance.
     *
     * @param {Plugin|pluginFunction|Processor} plugin PostCSS plugin
     *                                                 or {@link Processor}
     *                                                 with plugins.
     *
     * @example
     * const processor = postcss()
     *   .use(autoprefixer)
     *   .use(precss)
     *
     * @return {Processes} Current processor to make methods chain.
     */


    var _proto = Processor.prototype;

    _proto.use = function use(plugin) {
      this.plugins = this.plugins.concat(this.normalize([plugin]));
      return this;
    }
    /**
     * Parses source CSS and returns a {@link LazyResult} Promise proxy.
     * Because some plugins can be asynchronous it doesn’t make
     * any transformations. Transformations will be applied
     * in the {@link LazyResult} methods.
     *
     * @param {string|toString|Result} css String with input CSS or any object
     *                                     with a `toString()` method,
     *                                     like a Buffer. Optionally, send
     *                                     a {@link Result} instance
     *                                     and the processor will take
     *                                     the {@link Root} from it.
     * @param {processOptions} [opts]      Options.
     *
     * @return {LazyResult} Promise proxy.
     *
     * @example
     * processor.process(css, { from: 'a.css', to: 'a.out.css' })
     *   .then(result => {
     *      console.log(result.css)
     *   })
     */
    ;

    _proto.process = function (_process) {
      function process(_x) {
        return _process.apply(this, arguments);
      }

      process.toString = function () {
        return _process.toString();
      };

      return process;
    }(function (css, opts) {
      if (opts === void 0) {
        opts = {};
      }

      if (this.plugins.length === 0 && opts.parser === opts.stringifier) {
        if (process.env.NODE_ENV !== 'production') {
          if (typeof console !== 'undefined' && console.warn) {
            console.warn('You did not set any plugins, parser, or stringifier. ' + 'Right now, PostCSS does nothing. Pick plugins for your case ' + 'on https://www.postcss.parts/ and use them in postcss.config.js.');
          }
        }
      }

      return new _lazyResult.default(this, css, opts);
    });

    _proto.normalize = function normalize(plugins) {
      var normalized = [];

      for (var _iterator = plugins, _isArray = Array.isArray(_iterator), _i = 0, _iterator = _isArray ? _iterator : _iterator[Symbol.iterator]();;) {
        var _ref;

        if (_isArray) {
          if (_i >= _iterator.length) break;
          _ref = _iterator[_i++];
        } else {
          _i = _iterator.next();
          if (_i.done) break;
          _ref = _i.value;
        }

        var i = _ref;
        if (i.postcss) i = i.postcss;

        if (typeof i === 'object' && Array.isArray(i.plugins)) {
          normalized = normalized.concat(i.plugins);
        } else if (typeof i === 'function') {
          normalized.push(i);
        } else if (typeof i === 'object' && (i.parse || i.stringify)) {
          if (process.env.NODE_ENV !== 'production') {
            throw new Error('PostCSS syntaxes cannot be used as plugins. Instead, please use ' + 'one of the syntax/parser/stringifier options as outlined ' + 'in your PostCSS runner documentation.');
          }
        } else {
          throw new Error(i + ' is not a PostCSS plugin');
        }
      }

      return normalized;
    };

    return Processor;
  }();

  var _default = Processor;
  /**
   * @callback builder
   * @param {string} part          Part of generated CSS connected to this node.
   * @param {Node}   node          AST node.
   * @param {"start"|"end"} [type] Node’s part type.
   */

  /**
   * @callback parser
   *
   * @param {string|toString} css   String with input CSS or any object
   *                                with toString() method, like a Buffer.
   * @param {processOptions} [opts] Options with only `from` and `map` keys.
   *
   * @return {Root} PostCSS AST
   */

  /**
   * @callback stringifier
   *
   * @param {Node} node       Start node for stringifing. Usually {@link Root}.
   * @param {builder} builder Function to concatenate CSS from node’s parts
   *                          or generate string and source map.
   *
   * @return {void}
   */

  /**
   * @typedef {object} syntax
   * @property {parser} parse          Function to generate AST by string.
   * @property {stringifier} stringify Function to generate string by AST.
   */

  /**
   * @typedef {object} toString
   * @property {function} toString
   */

  /**
   * @callback pluginFunction
   * @param {Root} root     Parsed input CSS.
   * @param {Result} result Result to set warnings or check other plugins.
   */

  /**
   * @typedef {object} Plugin
   * @property {function} postcss PostCSS plugin function.
   */

  /**
   * @typedef {object} processOptions
   * @property {string} from             The path of the CSS source file.
   *                                     You should always set `from`,
   *                                     because it is used in source map
   *                                     generation and syntax error messages.
   * @property {string} to               The path where you’ll put the output
   *                                     CSS file. You should always set `to`
   *                                     to generate correct source maps.
   * @property {parser} parser           Function to generate AST by string.
   * @property {stringifier} stringifier Class to generate string by AST.
   * @property {syntax} syntax           Object with `parse` and `stringify`.
   * @property {object} map              Source map options.
   * @property {boolean} map.inline                    Does source map should
   *                                                   be embedded in the output
   *                                                   CSS as a base64-encoded
   *                                                   comment.
   * @property {string|object|false|function} map.prev Source map content
   *                                                   from a previous
   *                                                   processing step
   *                                                   (for example, Sass).
   *                                                   PostCSS will try to find
   *                                                   previous map automatically,
   *                                                   so you could disable it by
   *                                                   `false` value.
   * @property {boolean} map.sourcesContent            Does PostCSS should set
   *                                                   the origin content to map.
   * @property {string|false} map.annotation           Does PostCSS should set
   *                                                   annotation comment to map.
   * @property {string} map.from                       Override `from` in map’s
   *                                                   sources`.
   */

  exports.default = _default;
  module.exports = exports.default;

  });

  var vendor_1 = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  /**
   * Contains helpers for working with vendor prefixes.
   *
   * @example
   * const vendor = postcss.vendor
   *
   * @namespace vendor
   */
  var vendor = {
    /**
     * Returns the vendor prefix extracted from an input string.
     *
     * @param {string} prop String with or without vendor prefix.
     *
     * @return {string} vendor prefix or empty string
     *
     * @example
     * postcss.vendor.prefix('-moz-tab-size') //=> '-moz-'
     * postcss.vendor.prefix('tab-size')      //=> ''
     */
    prefix: function prefix(prop) {
      var match = prop.match(/^(-\w+-)/);

      if (match) {
        return match[0];
      }

      return '';
    },

    /**
       * Returns the input string stripped of its vendor prefix.
       *
       * @param {string} prop String with or without vendor prefix.
       *
       * @return {string} String name without vendor prefixes.
       *
       * @example
       * postcss.vendor.unprefixed('-moz-tab-size') //=> 'tab-size'
       */
    unprefixed: function unprefixed(prop) {
      return prop.replace(/^-\w+-/, '');
    }
  };
  var _default = vendor;
  exports.default = _default;
  module.exports = exports.default;

  });

  var postcss_1 = createCommonjsModule(function (module, exports) {

  exports.__esModule = true;
  exports.default = void 0;

  var _declaration = _interopRequireDefault(declaration);

  var _processor = _interopRequireDefault(processor);

  var _stringify = _interopRequireDefault(stringify_1);

  var _comment = _interopRequireDefault(comment);

  var _atRule = _interopRequireDefault(atRule);

  var _vendor = _interopRequireDefault(vendor_1);

  var _parse = _interopRequireDefault(parse_1);

  var _list = _interopRequireDefault(list_1);

  var _rule = _interopRequireDefault(rule);

  var _root = _interopRequireDefault(root);

  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

  /**
   * Create a new {@link Processor} instance that will apply `plugins`
   * as CSS processors.
   *
   * @param {Array.<Plugin|pluginFunction>|Processor} plugins PostCSS plugins.
   *        See {@link Processor#use} for plugin format.
   *
   * @return {Processor} Processor to process multiple CSS.
   *
   * @example
   * import postcss from 'postcss'
   *
   * postcss(plugins).process(css, { from, to }).then(result => {
   *   console.log(result.css)
   * })
   *
   * @namespace postcss
   */
  function postcss() {
    for (var _len = arguments.length, plugins = new Array(_len), _key = 0; _key < _len; _key++) {
      plugins[_key] = arguments[_key];
    }

    if (plugins.length === 1 && Array.isArray(plugins[0])) {
      plugins = plugins[0];
    }

    return new _processor.default(plugins);
  }
  /**
   * Creates a PostCSS plugin with a standard API.
   *
   * The newly-wrapped function will provide both the name and PostCSS
   * version of the plugin.
   *
   * ```js
   * const processor = postcss([replace])
   * processor.plugins[0].postcssPlugin  //=> 'postcss-replace'
   * processor.plugins[0].postcssVersion //=> '6.0.0'
   * ```
   *
   * The plugin function receives 2 arguments: {@link Root}
   * and {@link Result} instance. The function should mutate the provided
   * `Root` node. Alternatively, you can create a new `Root` node
   * and override the `result.root` property.
   *
   * ```js
   * const cleaner = postcss.plugin('postcss-cleaner', () => {
   *   return (root, result) => {
   *     result.root = postcss.root()
   *   }
   * })
   * ```
   *
   * As a convenience, plugins also expose a `process` method so that you can use
   * them as standalone tools.
   *
   * ```js
   * cleaner.process(css, processOpts, pluginOpts)
   * // This is equivalent to:
   * postcss([ cleaner(pluginOpts) ]).process(css, processOpts)
   * ```
   *
   * Asynchronous plugins should return a `Promise` instance.
   *
   * ```js
   * postcss.plugin('postcss-import', () => {
   *   return (root, result) => {
   *     return new Promise( (resolve, reject) => {
   *       fs.readFile('base.css', (base) => {
   *         root.prepend(base)
   *         resolve()
   *       })
   *     })
   *   }
   * })
   * ```
   *
   * Add warnings using the {@link Node#warn} method.
   * Send data to other plugins using the {@link Result#messages} array.
   *
   * ```js
   * postcss.plugin('postcss-caniuse-test', () => {
   *   return (root, result) => {
   *     root.walkDecls(decl => {
   *       if (!caniuse.support(decl.prop)) {
   *         decl.warn(result, 'Some browsers do not support ' + decl.prop)
   *       }
   *     })
   *   }
   * })
   * ```
   *
   * @param {string} name          PostCSS plugin name. Same as in `name`
   *                               property in `package.json`. It will be saved
   *                               in `plugin.postcssPlugin` property.
   * @param {function} initializer Will receive plugin options
   *                               and should return {@link pluginFunction}
   *
   * @return {Plugin} PostCSS plugin.
   */


  postcss.plugin = function plugin(name, initializer) {
    function creator() {
      var transformer = initializer.apply(void 0, arguments);
      transformer.postcssPlugin = name;
      transformer.postcssVersion = new _processor.default().version;
      return transformer;
    }

    var cache;
    Object.defineProperty(creator, 'postcss', {
      get: function get() {
        if (!cache) cache = creator();
        return cache;
      }
    });

    creator.process = function (css, processOpts, pluginOpts) {
      return postcss([creator(pluginOpts)]).process(css, processOpts);
    };

    return creator;
  };
  /**
   * Default function to convert a node tree into a CSS string.
   *
   * @param {Node} node       Start node for stringifing. Usually {@link Root}.
   * @param {builder} builder Function to concatenate CSS from node’s parts
   *                          or generate string and source map.
   *
   * @return {void}
   *
   * @function
   */


  postcss.stringify = _stringify.default;
  /**
   * Parses source css and returns a new {@link Root} node,
   * which contains the source CSS nodes.
   *
   * @param {string|toString} css   String with input CSS or any object
   *                                with toString() method, like a Buffer
   * @param {processOptions} [opts] Options with only `from` and `map` keys.
   *
   * @return {Root} PostCSS AST.
   *
   * @example
   * // Simple CSS concatenation with source map support
   * const root1 = postcss.parse(css1, { from: file1 })
   * const root2 = postcss.parse(css2, { from: file2 })
   * root1.append(root2).toResult().css
   *
   * @function
   */

  postcss.parse = _parse.default;
  /**
   * Contains the {@link vendor} module.
   *
   * @type {vendor}
   *
   * @example
   * postcss.vendor.unprefixed('-moz-tab') //=> ['tab']
   */

  postcss.vendor = _vendor.default;
  /**
   * Contains the {@link list} module.
   *
   * @member {list}
   *
   * @example
   * postcss.list.space('5px calc(10% + 5px)') //=> ['5px', 'calc(10% + 5px)']
   */

  postcss.list = _list.default;
  /**
   * Creates a new {@link Comment} node.
   *
   * @param {object} [defaults] Properties for the new node.
   *
   * @return {Comment} New comment node
   *
   * @example
   * postcss.comment({ text: 'test' })
   */

  postcss.comment = function (defaults) {
    return new _comment.default(defaults);
  };
  /**
   * Creates a new {@link AtRule} node.
   *
   * @param {object} [defaults] Properties for the new node.
   *
   * @return {AtRule} new at-rule node
   *
   * @example
   * postcss.atRule({ name: 'charset' }).toString() //=> "@charset"
   */


  postcss.atRule = function (defaults) {
    return new _atRule.default(defaults);
  };
  /**
   * Creates a new {@link Declaration} node.
   *
   * @param {object} [defaults] Properties for the new node.
   *
   * @return {Declaration} new declaration node
   *
   * @example
   * postcss.decl({ prop: 'color', value: 'red' }).toString() //=> "color: red"
   */


  postcss.decl = function (defaults) {
    return new _declaration.default(defaults);
  };
  /**
   * Creates a new {@link Rule} node.
   *
   * @param {object} [defaults] Properties for the new node.
   *
   * @return {Rule} new rule node
   *
   * @example
   * postcss.rule({ selector: 'a' }).toString() //=> "a {\n}"
   */


  postcss.rule = function (defaults) {
    return new _rule.default(defaults);
  };
  /**
   * Creates a new {@link Root} node.
   *
   * @param {object} [defaults] Properties for the new node.
   *
   * @return {Root} new root node.
   *
   * @example
   * postcss.root({ after: '\n' }).toString() //=> "\n"
   */


  postcss.root = function (defaults) {
    return new _root.default(defaults);
  };

  var _default = postcss;
  exports.default = _default;
  module.exports = exports.default;

  });

  // helpers
  var hasBackground = function (rule) { return /background[^:]*.*url[^;]+/gi.test(rule); };
  var isLocal = function (url) { return ['./', '../', '/'].map(function (path) { return url.indexOf(path) == 0; }).includes(true); };
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

  var PLUGIN_NAME = 'image-auto-size';
  var index = postcss_1.plugin(PLUGIN_NAME, function () {
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
              var _b = lib(image.path), width = _b.width, height = _b.height;
              declare.cloneAfter({
                  type: 'decl',
                  prop: 'width',
                  value: width + "px",
              }).cloneAfter({
                  type: 'decl',
                  prop: 'height',
                  value: height + "px",
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
              originURL: null,
          };
          if (hasBackground(ruleString)) {
              var _a = getImageURL(ruleString), originURL = _a[0], URL_1 = _a[1];
              image.type = getImageType(URL_1);
              image.URL = URL_1;
              image.originURL = originURL;
              if (imageSupported(image.URL)) {
                  image.path = path__default['default'].resolve(path__default['default'].dirname(styleFilePath), image.URL);
                  images.push(image);
              }
              else {
                  console.log("image not supported");
              }
          }
      });
      return images;
  }

  return index;

})));
//# sourceMappingURL=image-auto-size.js.map
