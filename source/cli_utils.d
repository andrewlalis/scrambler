module cli_utils;

import cipher_utils : ENCRYPTED_SUFFIX;
import std.typecons;

enum Action {
	ENCRYPT,
	DECRYPT
}

struct Params {
	Action action = Action.ENCRYPT;
	string target = ".";
	bool recursive = false;
	bool verbose = false;
	bool noSuffix = false;
	string passphraseFile = null;
}

int parseParams(string[] args, ref Params params) {
    import std.getopt;
    import std.stdio;
    import std.file : exists;
    import std.string : strip;
	bool isEncrypting;
	bool isDecrypting;
	getopt(
		args,
		"recursive|r", &params.recursive,
		"verbose|v", &params.verbose,
		"encrypt|e", &isEncrypting,
		"decrypt|d", &isDecrypting,
		"no-suffix|s", &params.noSuffix,
		"passphrase-file|p", &params.passphraseFile
	);
	if (isEncrypting && isDecrypting) {
		stderr.writeln("Invalid arguments: Cannot specify both the --encrypt and --decrypt flags.");
	}

	if (args.length > 1) {
		params.target = args[1];
		if (!exists(params.target)) {
			stderr.writefln!"Target \"%s\" doesn't exist."(params.target);
			return 1;
		}
	}

	if (isEncrypting) {
		params.action = Action.ENCRYPT;
	} else if (isDecrypting) {
		params.action = Action.DECRYPT;
	} else {
		params.action = determineBestAction(params.target);
	}
	return 0;
}

/** 
 * Determines the most appropriate action to perform on a target file or
 * directory, based on its contents.
 * Params:
 *   target = The target to check.
 * Returns: Whether to encrypt or decrypt.
 */
private Action determineBestAction(string target) {
	import std.file;
	import std.algorithm : endsWith;

	if (isFile(target)) {
		return endsWith(target, ENCRYPTED_SUFFIX) ? Action.DECRYPT : Action.ENCRYPT;
	} else if (isDir(target)) {
		foreach (DirEntry entry; dirEntries(target, SpanMode.breadth, false)) {
			if (entry.isFile && endsWith(entry.name, ENCRYPTED_SUFFIX)) return Action.DECRYPT;
		}
		return Action.ENCRYPT;
	} else {
		return Action.ENCRYPT;
	}
}

/** 
 * Prints a standard usage/help message to stdout.
 */
public void printUsage() {
    import std.stdio : writeln;
	writeln(q"HELP
Usage: scrambler [target] [options]
Scramber is a command-line tool for encrypting and decrypting files or entire
directories using a passphrase.

The following options are available:
  -e | --encrypt         Do an encryption operation on the target file or
                           directory.
  -d | --decrypt         Do a decryption operation on the target file or
                           directory.
  -p | --passphrase-file A file to read the passphrase from, instead of
                           prompting the user for a passphrase in the command
						   line.
  -r | --recursive       Recursively encrypt/decrypt nested directories.
  -v | --verbose         Show verbose output during runtime.
  -s | --no-suffix       Do not add the ".enc" suffix to files.

Encrypted files are suffixed with ".enc" to indicate that they're encrypted and
cannot be read as usual. If neither --encrypt nor --decrypt flags are provided,
Scrambler will try to determine which operation to do based on the presence of
".enc" file(s) at the target location.
HELP");
}

public Nullable!string getPassphrase(Params params) {
	import std.file;
	import std.stdio;
	import std.string : strip;
	if (params.passphraseFile !is null && params.passphraseFile.length > 0) {
		if (exists(params.passphraseFile) && isFile(params.passphraseFile)) {
			if (params.verbose) {
				writefln!"Reading passphrase from \"%s\""(params.passphraseFile);
			}
			return nullable(readText(params.passphraseFile).strip());
		} else {
			stderr.writefln!"Invalid or missing passphrase file: \"%s\""(params.passphraseFile);
			return Nullable!string.init;
		}
	}

	// No passphrase file specified, so read from stdin.
	write("Enter passphrase: ");
	string passphrase = readPassphrase();
	writeln();
	if (passphrase is null || passphrase.length == 0) {
		stderr.writeln("Invalid or missing passphrase.");
		return Nullable!string.init;
	}
	return nullable(passphrase);
}

/** 
 * Reads a passphrase from stdin while disabling terminal echoing, so that the
 * entered password does not appear.
 * Returns: The passphrase string, or null if we could not securely read it.
 */
public string readPassphrase() {
    import std.stdio;
    import std.string : strip;
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
        DWORD prev_con_mode;
		DWORD con_mode;
		DWORD dwRead;
		HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
		GetConsoleMode(hIn, &con_mode);
        GetConsoleMode(hIn, &prev_con_mode);
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
        SetConsoleMode(hIn, prev_con_mode);
		return password;
	} else {
        stderr.writeln("Cannot securely read password from terminal. Please supply a passphrase file with -p.");
		return null;
	}
}
