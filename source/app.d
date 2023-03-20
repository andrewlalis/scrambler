import std.stdio;
import std.path;
import std.file;
import std.algorithm : endsWith;
import std.string : strip;

import botan.block.block_cipher : BlockCipher;
import botan.block.aes : AES256;
import botan.hash.hash : HashFunction;
import botan.hash.sha2_32 : SHA256;

import cipher_utils;

int main(string[] args) {
	string action = "encrypt";
	if (args.length >= 2) {
		string command = args[1];
		if (command == "encrypt") {
			action = "encrypt";
		} else if (command == "decrypt") {
			action = "decrypt";
		} else {
			stderr.writefln!"Invalid action: %s"(command);
			return 1;
		}
	}

	string target = ".";
	if (args.length >= 3) {
		target = args[2];
		if (!exists(target)) {
			stderr.writefln!"Target \"%s\" doesn't exist."(target);
			return 1;
		}
	}

	BlockCipher cipher = null;
	// TODO: Use args to determine block cipher.
	writeln("Enter a password:");
	string password = readln().strip();

	HashFunction hash = new SHA256();
	auto secureKeyVector = hash.process(password);
	cipher = new AES256();
	cipher.setKey(secureKeyVector);

	ubyte[] buffer = new ubyte[cipher.blockSize];
	if (isDir(target)) {
		if (action == "encrypt") {
			encryptDir(target, cipher, buffer, true);
		} else if (action == "decrypt") {
			decryptDir(target, cipher, buffer, true);
		} else {
			stderr.writefln!"Unsupported action: %s"(action);
			return 1;
		}
	} else if (isFile(target)) {
		if (action == "encrypt") {
			encryptAndRemoveFile(target, cipher, buffer);
		} else if (action == "decrypt") {
			decryptAndRemoveFile(target, cipher, buffer);
		} else {
			stderr.writefln!"Unsupported action: %s"(action);
			return 1;
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
