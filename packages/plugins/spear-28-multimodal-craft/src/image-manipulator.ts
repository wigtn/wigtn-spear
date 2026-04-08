/**
 * SPEAR-28: Image Manipulator (Stub)
 *
 * Generates or manipulates adversarial images for arena scenarios.
 * Requires a canvas library for actual image manipulation.
 */

export interface ImageManipulatorOptions {
  /** Source image type */
  sourceType: 'cctv' | 'document' | 'sensor';
  /** Manipulation operation to perform */
  manipulation: 'overlay' | 'modify' | 'generate';
  /** Description of the desired manipulation */
  description: string;
}

/**
 * Manipulate or generate an adversarial image payload.
 *
 * @throws Always throws — requires canvas library.
 */
export async function manipulateImage(options: ImageManipulatorOptions): Promise<Buffer> {
  void options;
  throw new Error(
    'Image manipulation requires canvas library. Install @napi-rs/canvas.',
  );
}
