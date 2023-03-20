module cipher_utils;

import botan.block.block_cipher : BlockCipher;
import std.stdio;

public void encryptFile(string filename, string outputFilename, BlockCipher cipher, ref ubyte[] buffer) {
    assert(buffer.length == cipher.blockSize, "Buffer length must match cipher block size.");
    File fIn = File(filename, "rb");
    File fOut = File(outputFilename, "wb");
    // First, write one block containing the file's size.
    writeSizeBytes(buffer, fIn.size);
    cipher.encrypt(buffer);
    fOut.rawWrite(buffer);
    // Then write the rest of the file.
    foreach (ubyte[] chunk; fIn.byChunk(buffer)) {
        cipher.encrypt(buffer);
        fOut.rawWrite(buffer);
    }
    fIn.close();
    fOut.close();
}

public void decryptFile(string filename, string outputFilename, BlockCipher cipher, ref ubyte[] buffer) {
    assert(buffer.length == cipher.blockSize, "Buffer length must match cipher block size.");
    File fIn = File(filename, "rb");
    File fOut = File(outputFilename, "wb");
    // First, read one block containing the file's size.
    fIn.rawRead(buffer);
    cipher.decrypt(buffer);
    ulong size = readSizeBytes(buffer);
    ulong bytesWritten = 0;
    // Then read the rest of the file.
    foreach (ubyte[] chunk; fIn.byChunk(buffer)) {
        cipher.decrypt(buffer);
        size_t bytesToWrite = buffer.length;
        if (bytesWritten + buffer.length > size) {
            bytesToWrite = cast(size_t) (size - bytesWritten);
        }
        fOut.rawWrite(buffer[0 .. bytesToWrite]);
        bytesWritten += bytesToWrite;
    }
    fIn.close();
    fOut.close();
}

private void writeSizeBytes(ref ubyte[] bytes, ulong size) {
    assert(bytes.length >= 4, "Array length must be at least 4.");
    bytes[0] = size & 0xFF;
    bytes[1] = (size << 8) & 0xFF;
    bytes[2] = (size << 16) & 0xFF;
    bytes[3] = (size << 24) & 0xFF;
    if (bytes.length > 4) {
        for (size_t i = 4; i < bytes.length; i++) {
            bytes[i] = 0;
        }
    }
}

private ulong readSizeBytes(ref ubyte[] bytes) {
    assert(bytes.length >= 4, "Array length must be at least 4.");
    ulong size = 0;
    size += bytes[0];
    size += bytes[1] << 8;
    size += bytes[2] << 16;
    size += bytes[3] << 24;
    return size;
}