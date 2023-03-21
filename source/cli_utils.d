module cli_utils;

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
		"decrypt|d", &isDecrypting
	);
	if (isEncrypting && isDecrypting) {
		stderr.writeln("Invalid arguments: Cannot specify both the --encrypt and --decrypt flags.");
	}
	if (isEncrypting) {
		params.action = Action.ENCRYPT;
	} else if (isDecrypting) {
		params.action = Action.DECRYPT;
	} else {
		writeln("Determining if we should encrypt or decrypt");
		params.action = Action.ENCRYPT;
	}

	if (args.length > 1) {
		params.target = args[1];
		if (!exists(params.target)) {
			stderr.writefln!"Target \"%s\" doesn't exist."(params.target);
			return 1;
		}
	}
	return 0;
}

void printUsage() {
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
  -r | --recursive       Recursively encrypt/decrypt nested directories.
  -v | --verbose         Show verbose output during runtime.
  -s | --no-suffix       Do not add the ".enc" suffix to files.

Encrypted files are suffixed with ".enc" to indicate that they're encrypted and
cannot be read as usual. If neither --encrypt nor --decrypt flags are provided,
Scrambler will try to determine which operation to do based on the presence of
".enc" file(s) at the target location. It's recommended that you always do
provide an explicit --encrypt or --decrypt flag.
HELP");
}

string readPassphrase() {
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
        stderr.writeln("Cannot securely read password from terminal.");
		return null;
	}
}