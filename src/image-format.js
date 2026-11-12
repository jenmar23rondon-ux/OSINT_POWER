export const PNG_SIGNATURE = Buffer.from("89504e470d0a1a0a", "hex");

export function imageFormat(bytes) {
  if (bytes.subarray(0, 8).equals(PNG_SIGNATURE)) return "png";
  if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    if (bytes.at(-2) !== 0xff || bytes.at(-1) !== 0xd9)
      throw new Error("IMAGE_PARSE_FAILED");
    return "jpeg";
  }
  if (
    bytes.toString("ascii", 0, 4) === "RIFF" &&
    bytes.toString("ascii", 8, 12) === "WEBP"
  ) {
    if (bytes.length < 20 || bytes.readUInt32LE(4) + 8 !== bytes.length)
      throw new Error("IMAGE_PARSE_FAILED");
    return "webp";
  }
  const header = bytes.subarray(0, 4).toString("hex");
  if (["49492a00", "4d4d002a"].includes(header)) return "tiff";
  throw new Error("UNSUPPORTED_IMAGE_FORMAT");
}
