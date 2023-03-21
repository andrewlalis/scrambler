import std.stdio;
import std.path;
import std.file;
import std.algorithm : endsWith;
import std.string : strip;
import std.getopt;

import botan.block.block_cipher : BlockCipher;
import botan.block.aes : AES256;
import botan.hash.hash : HashFunction;
import botan.hash.sha2_32 : SHA256;

import cipher_utils;
import cli_utils;

int main(string[] args) {
	Params params;
	int result = parseParams(args, params);
	if (result != 0) {
		printUsage();
		return result;
	}

	BlockCipher cipher = null;
	// TODO: Use args to determine block cipher.
	writeln("Enter a passphrase:");
	string password = readPassphrase();
	if (password is null) {
		return 2;
	}

	HashFunction hash = new SHA256();
	auto secureKeyVector = hash.process(password);
	cipher = new AES256();
	cipher.setKey(secureKeyVector);

	ubyte[] buffer = new ubyte[cipher.blockSize];
	if (isDir(params.target)) {
		if (params.action == Action.ENCRYPT) {
			encryptDir(params.target, cipher, buffer, params.recursive);
		} else {
			decryptDir(params.target, cipher, buffer, params.recursive);
		}
	} else if (isFile(params.target)) {
		if (params.action == Action.ENCRYPT) {
			encryptAndRemoveFile(params.target, cipher, buffer);
		} else {
			decryptAndRemoveFile(params.target, cipher, buffer);
		}
	} else {
		stderr.writeln("Target is not a directory or file.");
		return 1;
	}
	return 0;
}


void encryptAndRemoveFile(string filename, BlockCipher cipher, ref ubyte[] buffer) {
	string encryptedFilename = filename ~ ".enc";
	encryptFile(filename, encryptedFilename, cipher, buffer);
	std.file.remove(filename);
}

void decryptAndRemoveFile(string filename, BlockCipher cipher, ref ubyte[] buffer) {
	string decryptedFilename = filename[0 .. $-4];
	decryptFile(filename, decryptedFilename, cipher, buffer);
	std.file.remove(filename);
}

void encryptDir(string dirname, BlockCipher cipher, ref ubyte[] buffer, bool recursive) {
	string[] dirsToTraverse;
	foreach (DirEntry entry; dirEntries(dirname, SpanMode.shallow, false)) {
		if (entry.isFile && !endsWith(entry.name, ".enc")) {
			encryptAndRemoveFile(entry.name, cipher, buffer);
		} else if (entry.isDir && recursive) {
			dirsToTraverse ~= entry.name;
		}
	}
	if (recursive) {
		foreach (string childDirname; dirsToTraverse) {
			encryptDir(childDirname, cipher, buffer, recursive);
		}
	}
}

void decryptDir(string dirname, BlockCipher cipher, ref ubyte[] buffer, bool recursive) {
	string[] dirsToTraverse;
	foreach (DirEntry entry; dirEntries(dirname, SpanMode.shallow, false)) {
		if (entry.isFile && endsWith(entry.name, ".enc")) {
			decryptAndRemoveFile(entry.name, cipher, buffer);
		} else if (entry.isDir && recursive) {
			dirsToTraverse ~= entry.name;
		}
	}
	if (recursive) {
		foreach (string childDirname; dirsToTraverse) {
			decryptDir(childDirname, cipher, buffer, recursive);
		}
	}
}
