/**
 * QRYPT – QR Code Protection
 * Developed by Team Cyber Titans
 *
 * Module: QR Code Decoding & Camera Engine (js/qr-engine.js)
 * Purpose: Handles image uploads, drag-and-drop, clipboard paste,
 *          and live camera video stream decoding using jsQR.
 */

(function (window) {
  'use strict';

  class QrEngine {
    constructor() {
      this.videoStream = null;
      this.cameraTimer = null;
      this.isBusyScanning = false;
      this.offscreenCanvas = document.createElement('canvas');
      this.offscreenCtx = this.offscreenCanvas.getContext('2d', { willReadFrequently: true });
    }

    /**
     * Checks if jsQR library is properly loaded and ready
     */
    isLibraryLoaded() {
      return typeof window.jsQR === 'function';
    }

    /**
     * Decodes an HTMLImageElement or ImageData
     * @param {HTMLImageElement|ImageBitmap} imageElement
     * @returns {Object|null} Decoded QR result or null
     */
    decodeImageElement(imageElement) {
      if (!this.isLibraryLoaded()) {
        throw new Error('QR decoding engine (jsQR) is not loaded.');
      }

      const width = imageElement.naturalWidth || imageElement.videoWidth || imageElement.width;
      const height = imageElement.naturalHeight || imageElement.videoHeight || imageElement.height;

      if (!width || !height) {
        throw new Error('Image dimensions are invalid or image could not be loaded.');
      }

      this.offscreenCanvas.width = width;
      this.offscreenCanvas.height = height;
      this.offscreenCtx.drawImage(imageElement, 0, 0, width, height);

      let imageData = this.offscreenCtx.getImageData(0, 0, width, height);
      let code = window.jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'attemptBoth'
      });

      // If initial decode failed, attempt a contrast/grayscale threshold pass
      if (!code && (width > 60 && height > 60)) {
        code = this.retryWithContrastPass(imageData);
      }

      return code ? { data: code.data, location: code.location } : null;
    }

    /**
     * Contrast enhancement pass for faint or low-contrast QR captures
     */
    retryWithContrastPass(imageData) {
      const data = new Uint8ClampedArray(imageData.data);
      const len = data.length;

      // Simple binarization thresholding
      for (let i = 0; i < len; i += 4) {
        // Luminance calculation
        const gray = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
        const val = gray > 128 ? 255 : 0;
        data[i] = val;
        data[i + 1] = val;
        data[i + 2] = val;
      }

      return window.jsQR(data, imageData.width, imageData.height, {
        inversionAttempts: 'attemptBoth'
      });
    }

    /**
     * Decodes a File or Blob image object
     * @param {File|Blob} file
     * @returns {Promise<Object>} Decoded result
     */
    decodeImageFile(file) {
      return new Promise((resolve, reject) => {
        if (!file.type.startsWith('image/')) {
          return reject(new Error('Selected file is not an image (expected PNG, JPG, WEBP, or SVG).'));
        }

        const objectUrl = URL.createObjectURL(file);
        const img = new Image();

        img.onload = () => {
          try {
            const result = this.decodeImageElement(img);
            URL.revokeObjectURL(objectUrl);
            if (result) {
              resolve({ success: true, text: result.data, imageSrc: objectUrl });
            } else {
              resolve({ success: false, text: null, error: 'No readable QR code found in the image. Please ensure the QR is clear and well-lit.' });
            }
          } catch (err) {
            URL.revokeObjectURL(objectUrl);
            reject(err);
          }
        };

        img.onerror = () => {
          URL.revokeObjectURL(objectUrl);
          reject(new Error('Failed to load image file. File may be corrupted.'));
        };

        img.src = objectUrl;
      });
    }

    /**
     * Starts camera video stream and periodic scanning
     * @param {HTMLVideoElement} videoElement
     * @param {Function} onScanSuccess - Callback receiving decoded text
     * @param {Function} onError - Callback receiving error message
     */
    async startCamera(videoElement, onScanSuccess, onError) {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Camera access is not supported by your browser or environment. Use HTTPS or localhost.');
      }

      this.stopCamera(videoElement);

      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: { ideal: 'environment' },
            width: { ideal: 1280 },
            height: { ideal: 720 }
          },
          audio: false
        });

        this.videoStream = stream;
        videoElement.srcObject = stream;
        videoElement.hidden = false;
        await videoElement.play();

        // Polling scan interval
        this.cameraTimer = setInterval(() => {
          if (this.isBusyScanning || videoElement.readyState < 2) return;
          this.isBusyScanning = true;

          try {
            const width = videoElement.videoWidth;
            const height = videoElement.videoHeight;
            if (width > 0 && height > 0) {
              this.offscreenCanvas.width = width;
              this.offscreenCanvas.height = height;
              this.offscreenCtx.drawImage(videoElement, 0, 0, width, height);

              const imageData = this.offscreenCtx.getImageData(0, 0, width, height);
              const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: 'dontInvert'
              });

              if (code && code.data) {
                // QR Detected!
                this.stopCamera(videoElement);
                if (typeof onScanSuccess === 'function') {
                  onScanSuccess(code.data);
                }
              }
            }
          } catch (scanErr) {
            console.error('Camera frame scan error:', scanErr);
          } finally {
            this.isBusyScanning = false;
          }
        }, 250);

        return true;
      } catch (err) {
        this.stopCamera(videoElement);
        let msg = 'Camera access was denied or is unavailable.';
        if (err.name === 'NotAllowedError') {
          msg = 'Camera permission was denied. Please allow camera access in browser permissions or upload an image.';
        } else if (err.name === 'NotFoundError') {
          msg = 'No video camera was found on this device.';
        }
        if (typeof onError === 'function') onError(msg);
        throw new Error(msg);
      }
    }

    /**
     * Stops camera stream and clears intervals
     * @param {HTMLVideoElement} videoElement
     */
    stopCamera(videoElement) {
      if (this.cameraTimer) {
        clearInterval(this.cameraTimer);
        this.cameraTimer = null;
      }

      if (this.videoStream) {
        this.videoStream.getTracks().forEach(track => {
          try { track.stop(); } catch (e) {}
        });
        this.videoStream = null;
      }

      if (videoElement) {
        videoElement.srcObject = null;
        videoElement.hidden = true;
      }

      this.isBusyScanning = false;
    }
  }

  // Export to window
  window.QryptEngine = new QrEngine();

})(window);
