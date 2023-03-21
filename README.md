# scrambler
Tool for encrypting and decrypting entire directories on-the-fly.

scrambler uses a block cipher and passphrase to encrypt and decrypt files in-place, as a means for quickly securing content without having to move things and/or create archives. scrambler appends a `.enc` extension to encrypted files, so it can use context clues to determine whether you want to perform encryption or decryption.

As of writing, this application uses an AES-256 block cipher, with a passphrase that's hashed by SHA-256.

## Usage
```shell
# Show help information.
scrambler -h
scrambler --help

# Encrypt or decrypt the current directory.
scrambler

# Encrypt or decrypt a specified directory.
scrambler my-dir

# Encrypt or decrypt a single file.
scrambler path/to/my/file.txt

# Encrypt or decrypt a directory recursively.
scrambler my-dir -r

# Add -v for verbose output.
scrambler myfile.txt -v

# Explicitly choose to encrypt with -e.
scrambler my-dir -e

# Explicitly choose to decrypt with -d.
scrambler my-encrypted-dir -d

# Supply a passphrase from a file.
scrambler my-dir -p my-passphrase.txt
```

## Download
You can download a compatible release from the [releases](https://github.com/andrewlalis/scrambler/releases) page. If you can't find any release that's available for your system, you can build it yourself:
```shell
git clone git@github.com:andrewlalis/scrambler.git
cd scrambler
dub build --build=release
```
