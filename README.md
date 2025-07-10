# Show Provenance Info

A tool to show the provenance information of a file or directory, presented at [Black Hat USA 2025](https://blackhat.com/us-25/briefings/schedule/#xunprotect-reverse-engineering-macos-xprotect-remediator-44791).

## Overview

Provenance Sandbox is a security mechanism introduced in macOS Ventura. When an application is launched, it is assigned an extended attribute called `com.apple.provenance`. If an application with this extended attribute is executed, it runs within the Provenance Sandbox. While running in this sandbox, any files it creates or modifies through the following file operations are also tagged with the `com.apple.provenance` extended attribute.

- create
- deleteextattr
- open (with write mode)
- setacl
- setattrlist
- setextattr
- setflags
- setmode
- setowner
- setutimes
- truncate
- link
- rename

This tool recursively scans files in a specified directory and displays information about the applications that performed the above operations on files based on the `com.apple.provenance` extended attribute.

For example, consider a case where Google Chrome has the `com.apple.provenance` extended attribute as shown below:

```
% xattr -px com.apple.provenance /Applications/Google\ Chrome.app
01 02 00 0B 5A A0 6C 3A 81 88 BE
```

When using Google Chrome to download "Firefox 138.0.4.dmg", the `com.apple.provenance` extended attribute is assigned as shown below:

```
% xattr -px com.apple.provenance ~/Downloads/Firefox\ 138.0.4.dmg
01 02 00 0B 5A A0 6C 3A 81 88 BE
```

By using the ShowProvenanceInfo tool, you can check which application created (or modified) Firefox 138.0.4.dmg as follows.

```
% sudo swift run -c release ShowProvenanceInfo -j ~/Downloads/Firefox\ 138.0.4.dmg
{
  "bundleId" : "com.google.Chrome",
  "creator" : "\/Applications\/Google Chrome.app",
  "filePath" : "file:\/\/\/Users\/ffri\/Downloads\/Firefox%20138.0.4.dmg",
  "pk" : "0xbe88813a6ca05a0b",
  "signingIdentifier" : "com.google.Chrome",
  "teamIdentifier" : "EQHXZ8M8AV",
  "timestamp" : 1732247128
}
```

## How to build & run

```
swift build
sudo swift run -c release ShowProvenanceInfo -j /path/to/file/or/directory
```

## Author

Koh M. Nakagawa (@tsunek0h) &copy; FFRI Security, Inc. 2025

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
