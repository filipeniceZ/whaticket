import crypto from "crypto";

const algorithm = "aes-256-ecb" as unknown as crypto.CipherCCMTypes;
const key = crypto.createHash("sha256").update(process.env.AES_KEY + new Date().toDateString()).digest() as unknown as crypto.CipherKey; // 32 bytes

export function encrypt(text: string): string {
  const cipher = crypto.createCipheriv(algorithm, key, null);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

export function decrypt(ciphertext: string): string {
  const decipher = crypto.createDecipheriv(algorithm, key, null);
  let decrypted = decipher.update(ciphertext, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}