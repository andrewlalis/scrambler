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
	if (args.length >= 2 && (args[1] == "-h" || args[1] == "--help")) {
		printUsage();
		return 0;
	}
	Params params;
	int result = parseParams(args, params);
	if (result != 0) {
		printUsage();
		return result;
	}

	auto nullablePassphrase = getPassphrase(params);
	if (nullablePassphrase.isNull) return 2;
	string passphrase = nullablePassphrase.get();

	HashFunction hash = new SHA256();
	auto secureKeyVector = hash.process(passphrase);
	BlockCipher cipher = new AES256();
	cipher.setKey(secureKeyVector);

	ubyte[] buffer = new ubyte[cipher.blockSize];
	if (isDir(params.target)) {
		if (params.action == Action.ENCRYPT) {
			encryptDir(params.target, cipher, buffer, params.recursive, params.verbose);
		} else {
			bool success = decryptDir(params.target, cipher, buffer, params.recursive, params.verbose);
			if (!success) {
				stderr.writeln("Decryption failed. The passphrase is probably incorrect.");
				return 3;
			}
		}
	} else if (isFile(params.target)) {
		if (params.action == Action.ENCRYPT) {
			encryptAndRemoveFile(params.target, cipher, buffer, params.verbose);
		} else {
			bool success = decryptAndRemoveFile(params.target, cipher, buffer, params.verbose);
			if (!success) {
				stderr.writeln("Decryption failed. The passphrase is probably incorrect.");
				return 3;
			}
		}
	}
	return 0;
}


void encryptAndRemoveFile(string filename, BlockCipher cipher, ref ubyte[] buffer, bool verbose) {
	string encryptedFilename = filename ~ ENCRYPTED_SUFFIX;
	encryptFile(filename, encryptedFilename, cipher, buffer, verbose);
	std.file.remove(filename);
}

bool decryptAndRemoveFile(string filename, BlockCipher cipher, ref ubyte[] buffer, bool verbose) {
	string decryptedFilename = filename[0 .. $-ENCRYPTED_SUFFIX.length];
	bool success = decryptFile(filename, decryptedFilename, cipher, buffer, verbose);
	if (!success) return false;
	std.file.remove(filename);
	return true;
}

void encryptDir(string dirname, BlockCipher cipher, ref ubyte[] buffer, bool recursive, bool verbose) {
	string[] dirsToTraverse;
	foreach (DirEntry entry; dirEntries(dirname, SpanMode.shallow, false)) {
		if (entry.isFile && !endsWith(entry.name, ENCRYPTED_SUFFIX)) {
			encryptAndRemoveFile(entry.name, cipher, buffer, verbose);
		} else if (entry.isDir && recursive) {
			dirsToTraverse ~= entry.name;
		}
	}
	if (recursive) {
		foreach (string childDirname; dirsToTraverse) {
			encryptDir(childDirname, cipher, buffer, recursive, verbose);
		}
	}
}

bool decryptDir(string dirname, BlockCipher cipher, ref ubyte[] buffer, bool recursive, bool verbose) {
	string[] dirsToTraverse;
	foreach (DirEntry entry; dirEntries(dirname, SpanMode.shallow, false)) {
		if (entry.isFile && endsWith(entry.name, ENCRYPTED_SUFFIX)) {
			bool success = decryptAndRemoveFile(entry.name, cipher, buffer, verbose);
			if (!success) return false;
		} else if (entry.isDir && recursive) {
			dirsToTraverse ~= entry.name;
		}
	}
	if (recursive) {
		foreach (string childDirname; dirsToTraverse) {
			bool success = decryptDir(childDirname, cipher, buffer, recursive, verbose);
			if (!success) return false;
		}
	}
	return true;
}
