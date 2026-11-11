# Parser interpretation corrections

START=e748ed69ae416317f10e4a39def48c3efc53a1e1

NetworkList preserves local SYSTEMTIME including milliseconds without inventing an offset. Task registration dates remain declared metadata. Startup input filesystem mtime remains explicitly observed input metadata, not target history; LNK arguments and working directory now parse correctly with warnings for damaged links.

MRU and ShellBag key LastWrite is associated only with the first ranked entry. ShellBag presence alone does not prove deletion. LastVisited uses aligned UTF-16 terminators and preserves binary PIDL data without inventing directory strings. Programs/CommonPrograms identities are corrected; SystemX86 remains a GUID without evidence OS architecture. Reference: https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid

Recycle content not observed is unknown, including metadata-only collections; lowercase metadata names no longer reference themselves. MFT invalid UTF-16 names preserve replacement display text, raw hex, and record timestamps.

Validation: 229 unittest tests passed. Synthetic actual CLI with tasks/startup/recyclebin/mft produced seven events and zero errors; uncertain primary timestamps absent; SHA-256 unchanged for every input. Regression failures were observed before the corresponding corrections. Real evidence, redirected known folders and all OS variants were not tested.

Push review: added lines/files and commit messages inspected; no source evidence, runtime dependencies, foreign code or private paths added. UI unchanged. Existing output keys remain, with uncertain timestamp/time_field now unknown and additive raw fields.
