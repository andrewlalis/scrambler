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

int main(string[] args) {
	Params params;
	int result = parseParams(args, params);
	if (result != 0) {
		printUsage();
		return result;
	}


	BlockCipher cipher = null;
	// TODO: Use args to determine block cipher.
	writeln("Enter a password:");
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

enum Action {
	ENCRYPT,
	DECRYPT
}

struct Params {
	Action action = Action.ENCRYPT;
	string target = ".";
	bool recursive = false;
	bool verbose = false;
}

int parseParams(string[] args, ref Params params) {
	getopt(
		args,
		"recursive|r", &params.recursive,
		"verbose|v", &params.verbose
	);
	if (args.length < 2) {
		stderr.writeln("Missing required action.");
		return 1;
	}
	string action = args[1].strip();
	if (action != "encrypt" && action != "decrypt") {
		stderr.writeln("Invalid action.");
		return 1;
	}
	if (action == "encrypt") {
		params.action = Action.ENCRYPT;
	} else if (action == "decrypt") {
		params.action = Action.DECRYPT;
	}

	if (args.length >= 3) {
		params.target = args[2];
		if (!exists(params.target)) {
			stderr.writefln!"Target \"%s\" doesn't exist."(params.target);
			return 1;
		}
	}
	return 0;
}

string readPassphrase() {
	version(Posix) {
		import core.sys.posix.termios : termios, tcgetattr, tcsetattr, ECHO;
		import core.sys.posix.stdio;
		termios term;
		tcgetattr(0, &term);
		term.c_lflag &= ~ECHO;
		tcsetattr(0, 0, &term);

		string passphrase = readln().strip();

		term.c_lflag |= ECHO;
		tcsetattr(0, 0, &term);

		return passphrase;
	} else version(Windows) {
		import core.sys.windows.windows;
		DWORD con_mode;
		DWORD dwRead;
		HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
		GetConsoleMode(hIn, &con_mode);
		SetConsoleMode(hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));

		string password = "";
		char BACKSPACE = 8;
		char RETURN = 13;
		char ch = 0;
		while (ReadConsoleA(hIn, &ch, 1, &dwRead, NULL) && ch != RETURN) {
			if (ch == BACKSPACE) {
				if (password.length > 0) {
					password = password[0 .. $ - 1];
				}
			} else {
				password ~= ch;
			}
		}
		return password;
	} else {
		stderr.writeln("Unsupported password reading.");
		return null;
	}
}

void printUsage() {
	writeln(q"HELP
Usage: scrambler <encrypt|decrypt> [target] [options]
Scramber is a command-line tool for "scrambling", or encrypting files with a
passphrase so they can only be read after they're decrypted using the same
passphrase.

Provide either the "encrypt" or "decrypt" command, followed by a target that's
either a directory, or an individual file. By default, the target is the
directory that Scrambler was invoked from.

The following options are available:
  -r | --recursive       Recursively encrypt/decrypt nested directories.
  -v | --verbose         Show verbose output during runtime.
HELP");
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
