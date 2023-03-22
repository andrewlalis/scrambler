module cipher_utils;

import botan.block.block_cipher : BlockCipher;
import std.stdio;
import std.file;
import std.datetime.stopwatch;

public const string ENCRYPTED_SUFFIX = ".enc";

public void encryptFile(string filename, string outputFilename, BlockCipher cipher, ref ubyte[] buffer, bool verbose) {
    assert(buffer.length == cipher.blockSize, "Buffer length must match cipher block size.");
    if (verbose) {
        writefln!"Encrypting file \"%s\" of %d bytes to \"%s\" using cipher %s."(
            filename,
            getSize(filename),
            outputFilename,
            cipher.name
        );
    }
    StopWatch sw = StopWatch(AutoStart.yes);
    File fIn = File(filename, "rb");
    File fOut = File(outputFilename, "wb");
    // First, write one block containing the file's size.
    writeSizeBytes(buffer, fIn.size);
    // Fill the rest of the block with an incrementing series of bytes, so we can easily validate decryption.
    if (buffer.length > 8) {
        ubyte marker = 1;
        for (size_t i = 8; i < buffer.length; i++) {
            buffer[i] = marker++;
        }
    }
    cipher.encrypt(buffer);
    fOut.rawWrite(buffer);
    // Then write the rest of the file.
    foreach (ubyte[] chunk; fIn.byChunk(buffer)) {
        cipher.encrypt(buffer);
        fOut.rawWrite(buffer);
    }
    fIn.close();
    fOut.close();
    sw.stop();
    if (verbose) {
        writefln!"  Encrypted file in %d ms, new size %d bytes."(sw.peek().total!"msecs", getSize(outputFilename));
    }
}

public bool decryptFile(string filename, string outputFilename, BlockCipher cipher, ref ubyte[] buffer, bool verbose) {
    assert(buffer.length == cipher.blockSize, "Buffer length must match cipher block size.");
    if (verbose) {
        writefln!"Decrypting file \"%s\" of %d bytes to \"%s\" using cipher %s."(
            filename,
            getSize(filename),
            outputFilename,
            cipher.name
        );
    }
    StopWatch sw = StopWatch(AutoStart.yes);
    File fIn = File(filename, "rb");
    // First, read one block containing the file's size.
    fIn.rawRead(buffer);
    cipher.decrypt(buffer);
    // Verify the sequence of values to ensure decryption was successful.
    if (buffer.length > 8 && !validateBufferDecryptionMarker(buffer[8..$], verbose)) {
        fIn.close();
        return false;
    }
    ulong size = readSizeBytes(buffer);
    if (verbose) {
        writefln!"  Original file had size of %d bytes."(size);
    }
    ulong bytesWritten = 0;
    File fOut = File(outputFilename, "wb");
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
    sw.stop();
    if (verbose) {
        writefln!"  Decrypted file in %d ms, new size %d bytes."(sw.peek().total!"msecs", getSize(outputFilename));
    }
    return true;
}

private bool validateBufferDecryptionMarker(ubyte[] bufferSlice, bool verbose) {
    ubyte expectedMarker = 1;
    for (size_t i = 0; i < bufferSlice.length; i++) {
        if (bufferSlice[i] != expectedMarker) {
            if (verbose) {
                writefln!"  Decryption validation failed. Expected byte at index %d to be %d, but got %d."(
                    i,
                    expectedMarker,
                    bufferSlice[i]
                );
            }
            return false;
        }
        expectedMarker++;
    }
    return true;
}

union LongByteArrayUnion {
    ulong longValue;
    ubyte[8] bytes;
}

private void writeSizeBytes(ref ubyte[] bytes, ulong size) {
    assert(bytes.length >= 8, "Array length must be at least 8.");
    LongByteArrayUnion u;
    u.longValue = size;
    for (size_t i = 0; i < 8; i++) bytes[i] = u.bytes[i];
    if (bytes.length > 8) {
        for (size_t i = 8; i < bytes.length; i++) {
            bytes[i] = 0;
        }
    }
}

private ulong readSizeBytes(ref ubyte[] bytes) {
    assert(bytes.length >= 8, "Array length must be at least 8.");
    LongByteArrayUnion u;
    for (size_t i = 0; i < 8; i++) u.bytes[i] = bytes[i];
    return u.longValue;
}

unittest {
    ubyte[] buffer = new ubyte[16];

    void doAssert(ulong size) {
        import std.format;
        writeSizeBytes(buffer, size);
        ulong r = readSizeBytes(buffer);
        assert(r == size, format!"Value read: %d does not match expected: %d."(r, size));
    }
    
    doAssert(0);
    doAssert(1);
    doAssert(42);
    doAssert(74_092_382_742_030);
}