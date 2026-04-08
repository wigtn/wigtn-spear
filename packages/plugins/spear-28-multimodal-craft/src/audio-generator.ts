/**
 * SPEAR-28: Audio Generator (Stub)
 *
 * Generates adversarial audio payloads for arena scenarios.
 * Requires a TTS API provider for actual audio generation.
 */

export interface AudioGeneratorOptions {
  /** Text content to convert to audio */
  text: string;
  /** Voice gender */
  voice: 'male' | 'female';
  /** Emotional tone of the generated audio */
  emotion: 'calm' | 'urgent' | 'panicked';
  /** Output audio format */
  outputFormat: 'wav' | 'mp3';
}

/**
 * Generate an adversarial audio payload.
 *
 * @throws Always throws — requires TTS API integration.
 */
export async function generateAudio(options: AudioGeneratorOptions): Promise<Buffer> {
  void options;
  throw new Error(
    'Audio generation requires TTS API integration. Set SPEAR_TTS_PROVIDER env var.',
  );
}
