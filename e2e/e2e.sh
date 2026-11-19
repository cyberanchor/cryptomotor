#!/usr/bin/env bash
# e2e.sh — end-to-end tests that drive the real cryptomotor binary on real files.
#
# usage: e2e/e2e.sh <cryptomotor> <cmcraft> <workdir> [<cryptomotor-3.1.0>]
#
#   cmcraft      independent implementation of the format (go build ./e2e/cmcraft)
#   3.1.0        optional release binary for the compatibility checks
#
# Prints PASS/FAIL lines and exits 1 if anything failed. TESTS="t03 t15" runs a
# subset. Every run uses --low-memory or a file that records 64 MiB, except on
# a machine with at least 8.5 GiB of free RAM, where the 4 GiB default is
# exercised as well. On smaller machines each run gets an address-space limit
# (VLIMIT KiB, default 3 GB), so an accidental 4 GiB Argon2id allocation fails
# at once instead of swapping.
set -u
BIN=$(readlink -f "$1"); CRAFT=$(readlink -f "$2"); WORK=$3; OLD=${4:-}
[[ -n $OLD ]] && OLD=$(readlink -f "$OLD")
HERE=$(dirname "$(readlink -f "$0")")
mkdir -p "$WORK"; WORK=$(readlink -f "$WORK")
PW='pw-Live-123'
LM=(--low-memory --no-progress)
npass=0 nfail=0
RESULTS=$WORK/results.txt; : >"$RESULTS"
OUT=$WORK/.stdout ERR=$WORK/.stderr RC=0

AVAIL_MB=$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || echo 0)
BIG=0
if ((AVAIL_MB >= 8704)); then BIG=1; fi
VLIMIT=${VLIMIT:-3000000}
((BIG)) && VLIMIT=unlimited

log()  { printf '%s\n' "$*" | tee -a "$RESULTS"; }
pass() { npass=$((npass + 1)); log "PASS  $1  $2"; }
fail() { nfail=$((nfail + 1)); log "FAIL  $1  $2"; }
section() { log ""; log "== $*"; }

# runb <binary> [args...] — run under the address-space limit; sets RC, OUT, ERR.
runb() { local b=$1; shift; (ulimit -v "$VLIMIT"; exec "$b" "$@") >"$OUT" 2>"$ERR" </dev/null; RC=$?; }
cm()   { runb "$BIN" "$@"; }
has()  { grep -aqF -- "$1" "$OUT" "$ERR"; }
errline() { grep -a -m1 -E 'ERROR|panic|fatal' "$ERR" | cat -v | cut -c1-160; }
sha()  { sha256sum "$1" | cut -d' ' -f1; }
only() { local f=("$1"/*); [[ ${#f[@]} -eq 1 && -e ${f[0]} ]] && printf '%s' "${f[0]}"; }
count() { local f=("$1"/* "$1"/.[!.]*); local n=0 x; for x in "${f[@]}"; do [[ -e $x || -L $x ]] && n=$((n + 1)); done; echo $n; }
hexat() { od -An -tx1 -j "$2" -N "$3" "$1" | tr -d ' \n'; }
setbytes() { printf "$(sed 's/../\\x&/g' <<<"$3")" | dd of="$1" bs=1 seek="$2" conv=notrunc status=none; }
flipbyte() { local b; b=$(hexat "$1" "$2" 1); setbytes "$1" "$2" "$(printf '%02x' $((0x$b ^ 0xff)))"; }
# encsize <plaintext bytes> <chunk bytes>
encsize() { local c=$(( ($1 + $2 - 1) / $2 )); echo $((810 + $1 + c * 20 + 4)); }
summary() { grep -ao '[0-9]* processed, [0-9]* skipped, [0-9]* failed' "$ERR" | tail -1; }
LOWCHUNK=524288

# ---------------------------------------------------------------------------
t01() {
	section "T01 command-line validation"
	local d=$WORK/t01; mkdir -p "$d/dir"; printf 'abcdef' >"$d/f.txt"
	check() { # id expected-rc text args...
		local id=$1 want=$2 text=$3; shift 3; cm "$@"
		if [[ $RC -eq $want ]] && { [[ -z $text ]] || has "$text"; }; then pass "$id" "rc=$RC: ${*:0:3}"
		else fail "$id" "rc=$RC (want $want, '$text') for: $* :: $(errline)"; fi
	}
	check T01.1 0 "Usage:" --help
	check T01.2 1 "specify one of"
	check T01.3 2 "flag provided but not defined" --bogus
	check T01.4 1 "only one of" --encrypt --decrypt --file "$d/f.txt"
	check T01.5 1 "requires --folder or --file" --encrypt
	check T01.6 1 "not both" --encrypt --file "$d/f.txt" --folder "$d/dir"
	check T01.7 1 "not both" --encrypt --file "$d/f.txt" --password a --password-file "$d/f.txt"
	check T01.8 1 "no such file" --encrypt --file "$d/missing"
	check T01.9 1 "is a directory" --encrypt --file "$d/dir"
	check T01.10 1 "is not a directory" --encrypt --folder "$d/f.txt"
	check T01.11 1 "--analyze requires --file" --analyze
	check T01.12 1 "read password file" --encrypt --file "$d/f.txt" --password-file "$d/missing" "${LM[@]}"
	: >"$d/empty.pw"; check T01.13 1 "password is empty" --encrypt --file "$d/f.txt" --password-file "$d/empty.pw" "${LM[@]}"
	printf '\r\n\n' >"$d/nl.pw"; check T01.14 1 "password is empty" --encrypt --file "$d/f.txt" --password-file "$d/nl.pw" "${LM[@]}"
	check T01.15 1 "stdin is not a terminal" --encrypt --file "$d/f.txt" "${LM[@]}"
	check T01.16 1 "unexpected argument \"stray\"" --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}" stray
	[[ ! -e $d/encrypted ]] && pass T01.17 "no output after a rejected command line" || fail T01.17 "encrypted/ created"
	check T01.18 1 "logger init: open log file" --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}" --log "$d/dir"
}

t02() {
	section "T02 version"
	cm --help
	local v; v=$(grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' "$ERR" | head -1)
	if [[ -n ${EXPECT_VERSION:-} && $v != "v$EXPECT_VERSION" ]]; then fail T02 "banner says $v, expected v$EXPECT_VERSION"
	else pass T02 "banner reports $v"; fi
}

t03() {
	section "T03 round trip, sizes x ciphers (64 MiB Argon2id, 512 KiB chunks)"
	local c size sub enc dec flag
	for c in xchacha aes; do
		flag=(); [[ $c == aes ]] && flag=(--aes)
		for size in 0 1 3 4 1000 65536 524288 524289 1048579 5242880; do
			sub=$WORK/t03/$c-$size; mkdir -p "$sub"
			head -c "$size" /dev/urandom >"$sub/data_$size.bin"
			cm --encrypt --file "$sub/data_$size.bin" --password "$PW" "${LM[@]}" "${flag[@]}"
			enc=$(only "$sub/encrypted")
			if [[ $RC -ne 0 || -z $enc ]]; then fail T03 "$c size=$size encrypt rc=$RC $(errline)"; continue; fi
			local ok=1 why=
			[[ $(basename "$enc") =~ ^[0-9a-f]{32}$ ]] || { ok=0; why+=" name=$(basename "$enc")"; }
			[[ $(stat -c %s "$enc") -eq $(encsize "$size" $LOWCHUNK) ]] || { ok=0; why+=" encsize=$(stat -c %s "$enc")/$(encsize "$size" $LOWCHUNK)"; }
			[[ $(hexat "$enc" 8 2) == "$([[ $c == aes ]] && echo 01 || echo 02)01" ]] || { ok=0; why+=" cipher+kdf=$(hexat "$enc" 8 2)"; }
			cm --decrypt --file "$enc" --password "$PW" --no-progress
			dec=$sub/encrypted/decrypted/data_$size.bin
			[[ $RC -eq 0 && -f $dec ]] || { ok=0; why+=" decrypt rc=$RC $(errline)"; }
			[[ -f $dec && $(sha "$dec") == $(sha "$sub/data_$size.bin") ]] || { ok=0; why+=" content differs"; }
			[[ $(count "$sub/encrypted/decrypted") -eq 1 ]] || { ok=0; why+=" leftovers"; }
			((ok)) && pass T03 "$c size=$size, $(encsize "$size" $LOWCHUNK) bytes, decrypted without --low-memory" || fail T03 "$c size=$size:$why"
		done
	done
	local e4 p; e4=$(compgen -G "$WORK/t03/aes-4/encrypted/*" | grep -v '/decrypted$' | head -1)
	p=$(stat -c '%a' "$e4" "$WORK/t03/aes-4/encrypted/decrypted/data_4.bin" | paste -sd/)
	[[ $p == 640/600 ]] && pass T03.perm "encrypted 640, decrypted 600 (umask $(umask))" || fail T03.perm "modes $p"
}

t05() {
	section "T05 unusual file names"
	local d=$WORK/t05 name long i=0
	long=$(printf 'a%.0s' {1..251}).bin
	for name in 'документ 密码 αβγ.txt' $'line1\nline2.txt' '-rf' "$long" '.env' 'a"b'"'"'c$(id).txt' '..\..\evil.bat' $'\e[31mred.txt'; do
		i=$((i + 1)); mkdir -p "$d/$i"
		printf 'content of file %s\n' "$i" >"$d/$i/$name"
		cm --encrypt --file "$d/$i/$name" --password "$PW" "${LM[@]}"
		local enc; enc=$(only "$d/$i/encrypted")
		[[ -n $enc ]] && cm --decrypt --file "$enc" --password "$PW" "${LM[@]}"
		if [[ $RC -eq 0 && -f "$d/$i/encrypted/decrypted/$name" ]] && cmp -s "$d/$i/$name" "$d/$i/encrypted/decrypted/$name" &&
			! grep -aq $'\e' "$ERR"; then
			pass T05 "name preserved, messages escaped: $(printf '%q' "$name" | cut -c1-50)"
		else fail T05 "name $(printf '%q' "$name" | cut -c1-50): rc=$RC $(errline)"; fi
	done
}

t06() {
	section "T06 memory and chunk boundaries"
	local d=$WORK/t06 size enc m1 m2
	for size in 67108864 67108865; do
		rm -rf "$d"; mkdir -p "$d"
		truncate -s "$size" "$d/big.bin"
		(ulimit -v "$VLIMIT"; exec python3 -I "$HERE/maxrss.py" "$BIN" --encrypt --file "$d/big.bin" --password "$PW" "${LM[@]}") >"$OUT" 2>"$ERR"; RC=$?
		m1=$(grep -o 'maxrss=[0-9.]*' "$ERR" | cut -d= -f2)
		enc=$(only "$d/encrypted")
		[[ $RC -eq 0 && -n $enc ]] || { fail T06 "size=$size encrypt rc=$RC $(errline)"; continue; }
		(ulimit -v "$VLIMIT"; exec python3 -I "$HERE/maxrss.py" "$BIN" --decrypt --file "$enc" --password "$PW" --no-progress) >"$OUT" 2>"$ERR"; RC=$?
		m2=$(grep -o 'maxrss=[0-9.]*' "$ERR" | cut -d= -f2)
		if [[ $RC -eq 0 && $(stat -c %s "$enc") -eq $(encsize "$size" $LOWCHUNK) ]] && cmp -s "$d/big.bin" "$d/encrypted/decrypted/big.bin" &&
			awk -v a="$m1" -v b="$m2" 'BEGIN { exit !(a < 120 && b < 120) }'; then
			pass T06 "size=$size: peak RSS encrypt ${m1} MiB, decrypt ${m2} MiB (limit 120)"
		else fail T06 "size=$size rc=$RC rss=$m1/$m2 $(errline)"; fi
	done
	rm -rf "$d"
}

t07() {
	section "T07 compatibility with 3.1.0 and the independent implementation"
	local d=$WORK/t07; mkdir -p "$d"; head -c 70000 /dev/urandom >"$d/x.bin"
	local flag enc
	for flag in "" --aes; do
		rm -rf "$d/encrypted"
		cm --encrypt --file "$d/x.bin" --password "$PW" "${LM[@]}" $flag; enc=$(only "$d/encrypted")
		if "$CRAFT" decrypt -in "$enc" -password "$PW" >"$OUT" 2>"$ERR" && grep -q "kdf=0x01 .*sha256=$(sha "$d/x.bin")" "$OUT"; then
			pass T07.1 "independent decoder reads a ${flag:-xchacha} file from this version"
		else fail T07.1 "cmcraft: $(cat "$OUT" "$ERR")"; fi
		if [[ -n $OLD ]]; then
			runb "$OLD" --decrypt --file "$enc" --password "$PW" "${LM[@]}"
			[[ $RC -eq 0 ]] && cmp -s "$d/x.bin" "$d/encrypted/decrypted/x.bin" && pass T07.2 "3.1.0 decrypts a ${flag:-xchacha} file from this version (with --low-memory)" || fail T07.2 "rc=$RC $(errline)"
			rm -rf "$d/encrypted"
			runb "$OLD" --encrypt --file "$d/x.bin" --password "$PW" "${LM[@]}" $flag; enc=$(only "$d/encrypted")
			cm --decrypt --file "$enc" --password "$PW" --no-progress
			[[ $RC -eq 0 ]] && cmp -s "$d/x.bin" "$d/encrypted/decrypted/x.bin" && pass T07.3 "this version decrypts a 3.1.0 ${flag:-xchacha} file without --low-memory" || fail T07.3 "rc=$RC $(errline)"
		fi
	done
	rm -f "$d/c.cm"; "$CRAFT" craft -in "$d/x.bin" -out "$d/c.cm" -password "$PW" -name x.bin
	rm -rf "$d/decrypted"; cm --decrypt --file "$d/c.cm" --password "$PW" --no-progress
	[[ $RC -eq 0 ]] && cmp -s "$d/x.bin" "$d/decrypted/x.bin" && pass T07.4 "decrypts a file written by the independent encoder" || fail T07.4 "rc=$RC $(errline)"
}

t08() {
	section "T08 password sources"
	local d=$WORK/t08; mkdir -p "$d"; printf 'password source test\n' >"$d/p.txt"
	try() { # id description password-used-for-encryption file-content
		rm -rf "$d/encrypted"; cm --encrypt --file "$d/p.txt" --password "$3" "${LM[@]}"; local enc; enc=$(only "$d/encrypted")
		printf '%b' "$4" >"$d/pwfile"
		cm --decrypt --file "$enc" --password-file "$d/pwfile" --no-progress
		[[ $RC -eq 0 ]] && pass "$1" "$2" || fail "$1" "$2: rc=$RC $(errline)"
	}
	try T08.1 "file 'pw\\n' = --password pw" pw 'pw\n'
	try T08.2 "file 'pw\\r\\n' = --password pw" pw 'pw\r\n'
	try T08.3 "file with UTF-8 BOM = --password pw" pw '\xef\xbb\xbfpw\r\n'
	try T08.4 "spaces and tabs are kept" $'  p w\t ' '  p w\t \n'
	rm -rf "$d/encrypted"
	printf '%s\n' "$PW" | script -q -e -c "bash -c 'ulimit -v $VLIMIT; exec \"$BIN\" --encrypt --file \"$d/p.txt\" --low-memory --no-progress'" /dev/null >"$OUT" 2>&1; RC=$?
	local enc; enc=$(only "$d/encrypted")
	if [[ $RC -eq 0 && -n $enc ]]; then
		cm --decrypt --file "$enc" --password "$PW" --no-progress
		[[ $RC -eq 0 ]] && pass T08.5 "interactive prompt (pty) encrypts, --password decrypts" || fail T08.5 "decrypt rc=$RC"
	else fail T08.5 "pty run rc=$RC: $(tr -d '\r' <"$OUT" | tail -2)"; fi
	local longpw; longpw=$(head -c 4000 /dev/urandom | base64 -w0 | head -c 5000)
	rm -rf "$d/encrypted"; cm --encrypt --file "$d/p.txt" --password "$longpw" "${LM[@]}"
	[[ $RC -eq 0 ]] && has "exceeds recommended maximum" && pass T08.6 "5000-byte password: warning, works" || fail T08.6 "rc=$RC"
}

t09() {
	section "T09 wrong password"
	local d=$WORK/t09; mkdir -p "$d/src"; printf 'one\n' >"$d/src/one.txt"; printf 'two\n' >"$d/src/two.txt"
	cm --encrypt --folder "$d/src" --password "$PW" "${LM[@]}"
	[[ $RC -eq 0 && $(summary) == "2 processed, 0 skipped, 0 failed" ]] && pass T09.1 "folder encrypt: $(summary)" || fail T09.1 "rc=$RC $(summary)"
	local enc; enc=$(compgen -G "$d/src/encrypted/*" | head -1)
	cm --decrypt --file "$enc" --password wrong --no-progress
	[[ $RC -eq 1 ]] && has "HMAC verification failed" && [[ ! -e $d/src/encrypted/decrypted ]] &&
		pass T09.2 "single file: rc=1, nothing created" || fail T09.2 "rc=$RC $(errline)"
	cm --decrypt --folder "$d/src/encrypted" --password wrong --no-progress
	[[ $RC -eq 1 ]] && has "2 of 2" && pass T09.3 "folder: rc=1, $(summary)" || fail T09.3 "rc=$RC $(summary)"
}

t10() {
	section "T10 folder with special entries"
	local d=$WORK/t10/src; mkdir -p "$d/sub"
	printf 'aaaaaaaaaa' >"$d/a.txt"; head -c 2048 /dev/urandom >"$d/b.bin"; : >"$d/empty.txt"; printf 'abc' >"$d/tiny"
	printf 'hidden....' >"$d/.hidden"; printf 'nested file' >"$d/sub/inner.txt"
	ln -s a.txt "$d/link_file"; ln -s sub "$d/link_dir"; ln -s /nonexistent/x "$d/dangling"
	mkfifo "$d/fifo"; printf 'secret....' >"$d/noread"; chmod 000 "$d/noread"
	local t0=$SECONDS
	cm --encrypt --folder "$d" --password "$PW" "${LM[@]}" --verbose
	chmod 600 "$d/noread"
	local want="6 processed, 1 skipped, 2 failed"
	[[ $(id -u) -eq 0 ]] && want="7 processed, 1 skipped, 1 failed"
	if [[ $RC -eq 1 && $(summary) == "$want" ]] && has "Skipping" && has "named pipe"; then
		pass T10.1 "rc=1, $(summary) in $((SECONDS - t0))s: FIFO skipped, dangling link and unreadable file failed"
	else fail T10.1 "rc=$RC $(summary)"; fi
	printf 'not encrypted' >"$d/encrypted/README.txt"; printf 'CMv3' >"$d/encrypted/short"; mkfifo "$d/encrypted/pipe"
	timeout 60 bash -c "ulimit -v $VLIMIT; exec \"$BIN\" --decrypt --folder \"$d/encrypted\" --password \"$PW\" --no-progress --verbose" >"$OUT" 2>"$ERR"; RC=$?
	if [[ $RC -eq 0 && $(summary) == "${want%%,*}, 3 skipped, 0 failed" ]] && cmp -s "$d/a.txt" "$d/encrypted/decrypted/link_file" &&
		[[ -f $d/encrypted/decrypted/empty.txt && ! -s $d/encrypted/decrypted/empty.txt ]]; then
		pass T10.2 "folder decrypt: $(summary); no hang on a named pipe, empty file restored"
	else fail T10.2 "rc=$RC (124 = hang) $(summary)"; fi
}

t12() {
	section "T12 existing output files"
	local d=$WORK/t12; mkdir -p "$d"; printf 'version 1 of notes\n' >"$d/notes.txt"
	cm --encrypt --file "$d/notes.txt" --password "$PW" "${LM[@]}"; local enc; enc=$(only "$d/encrypted")
	mkdir -p "$d/encrypted/decrypted"; printf 'newer notes\n' >"$d/encrypted/decrypted/notes.txt"
	cm --decrypt --file "$enc" --password "$PW" --no-progress
	[[ $RC -eq 1 ]] && has "already exists" && grep -q 'newer notes' "$d/encrypted/decrypted/notes.txt" && [[ $(count "$d/encrypted/decrypted") -eq 1 ]] &&
		pass T12.1 "existing file kept: rc=1 'already exists'" || fail T12.1 "rc=$RC $(errline)"
	cm --decrypt --file "$enc" --password "$PW" --no-progress --force
	[[ $RC -eq 0 ]] && grep -q 'version 1' "$d/encrypted/decrypted/notes.txt" && pass T12.2 "--force replaces it" || fail T12.2 "rc=$RC"
	rm -f "$d/encrypted/decrypted/notes.txt"; mkdir "$d/encrypted/decrypted/notes.txt"
	cm --decrypt --file "$enc" --password "$PW" --no-progress --force
	[[ $RC -eq 1 && $(count "$d/encrypted/decrypted") -eq 1 ]] && pass T12.3 "a directory is never replaced, temp removed" || fail T12.3 "rc=$RC"
}

t13() {
	section "T13 two encrypted files with the same name"
	local d=$WORK/t13; mkdir -p "$d/a" "$d/b" "$d/inbox"
	printf 'report from A\n' >"$d/a/report.txt"; printf 'report from B\n' >"$d/b/report.txt"
	cm --encrypt --file "$d/a/report.txt" --password "$PW" "${LM[@]}"; mv "$d"/a/encrypted/* "$d/inbox/"
	cm --encrypt --file "$d/b/report.txt" --password "$PW" "${LM[@]}"; mv "$d"/b/encrypted/* "$d/inbox/"
	cm --decrypt --folder "$d/inbox" --password "$PW" --no-progress
	[[ $RC -eq 1 && $(summary) == "1 processed, 0 skipped, 1 failed" ]] && has "already exists" && [[ $(count "$d/inbox/decrypted") -eq 1 ]] &&
		pass T13 "second report.txt fails with 'already exists', rc=1" || fail T13 "rc=$RC $(summary)"
}

t14() {
	section "T14 --dry-run"
	local d=$WORK/t14; mkdir -p "$d"; printf 'dry run data\n' >"$d/f.txt"
	cm --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}" --dry-run
	[[ $RC -eq 0 && ! -e $d/encrypted ]] && has "Dry run" && pass T14.1 "encrypt: nothing created" || fail T14.1 "rc=$RC"
	cm --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}"; local enc; enc=$(only "$d/encrypted")
	cm --decrypt --file "$enc" --password "$PW" --no-progress --dry-run
	[[ $RC -eq 0 && ! -e $d/encrypted/decrypted ]] && pass T14.2 "decrypt: nothing created" || fail T14.2 "rc=$RC"
	cm --decrypt --file "$enc" --password wrong --no-progress --dry-run
	[[ $RC -eq 1 ]] && pass T14.3 "decrypt dry run still checks the password" || fail T14.3 "rc=$RC"
}

t15() {
	section "T15 header and payload tampering (correct password)"
	local d=$WORK/t15; mkdir -p "$d/src"
	head -c 5000 /dev/urandom >"$d/src/secret.txt"
	cm --encrypt --file "$d/src/secret.txt" --password "$PW" "${LM[@]}"; local X; X=$(only "$d/src/encrypted")
	cm --encrypt --file "$d/src/secret.txt" --password "$PW" "${LM[@]}" --aes
	local A; A=$(compgen -G "$d/src/encrypted/*" | grep -v "$X" | head -1)
	# tcase <id> <base> <what> <op> <expect: ok|reject> <text...>
	tcase() {
		local id=$1 base=$2 what=$3 op=$4 expect=$5; shift 5
		local f=$d/t/case.cm; rm -rf "$d/t"; mkdir -p "$d/t"; cp "$base" "$f"
		eval "$op"
		cm --decrypt --file "$f" --password "$PW" --no-progress
		local left; left=$(count "$d/t/decrypted")
		if [[ $expect == ok ]]; then
			[[ $RC -eq 0 && $left -eq 1 ]] && cmp -s "$d/src/secret.txt" "$d/t/decrypted/secret.txt" &&
				pass "$id" "$what -> decrypts, same content" || fail "$id" "$what -> rc=$RC $(errline)"
			return
		fi
		local t matched=0
		for t in "$@"; do has "$t" && matched=1; done
		if [[ $RC -eq 1 && $matched -eq 1 && $left -eq 0 ]] && ! grep -aq '^panic:' "$ERR"; then pass "$id" "$what -> rc=1: $(errline | cut -c1-110)"
		else fail "$id" "$what -> rc=$RC left=$left (want one of: $*) :: $(errline)"; fi
	}
	tcase T15.1 "$X" "signature byte flipped" 'flipbyte $f 0' reject "invalid file signature"
	tcase T15.2 "$X" "cipher 0x02 -> 0x01" 'setbytes $f 8 01' reject "unused nonce bytes"
	tcase T15.3 "$X" "cipher -> 0x03" 'setbytes $f 8 03' reject "unknown cipher ID 0x03"
	tcase T15.4 "$X" "KDF byte -> 0x7f" 'setbytes $f 9 7f' reject "unknown key derivation mode 0x7f"
	tcase T15.5 "$X" "KDF byte 0x01 -> 0x02" 'setbytes $f 9 02' reject "not enough free memory" "HMAC verification failed"
	tcase T15.6 "$X" "KDF byte 0x01 -> 0x00 (looks like 3.1.0)" 'setbytes $f 9 00' ok
	tcase T15.7 "$X" "salt byte flipped" 'flipbyte $f 10' reject "HMAC verification failed"
	tcase T15.8 "$X" "payload nonce flipped" 'flipbyte $f 97' reject "stream decrypt"
	tcase T15.9 "$X" "filename nonce flipped" 'flipbyte $f 121' reject "decrypt filename"
	tcase T15.10 "$X" "hash nonce flipped" 'flipbyte $f 145' reject "decrypt hash"
	tcase T15.11 "$X" "HMAC flipped" 'flipbyte $f 146' reject "HMAC verification failed"
	tcase T15.12 "$X" "padded name length -> 0" 'setbytes $f 210 00000000' reject "padded name length field"
	tcase T15.13 "$X" "encrypted name flipped" 'flipbyte $f 214' reject "HMAC verification failed"
	tcase T15.14 "$X" "encrypted hash flipped" 'flipbyte $f 726' reject "HMAC verification failed"
	tcase T15.15 "$X" "OrigNameLen -> 0xffffffff" 'setbytes $f 806 ffffffff' reject "name length field is 4294967295"
	tcase T15.16 "$X" "OrigNameLen -> 497" 'setbytes $f 806 000001f1' reject "name length field is 497"
	tcase T15.17 "$X" "OrigNameLen 10 -> 3" 'setbytes $f 806 00000003' reject "name length field says 3"
	tcase T15.18 "$X" "OrigNameLen -> 0" 'setbytes $f 806 00000000' reject "name length field says 0"
	tcase T15.19 "$X" "OrigNameLen 10 -> 14" 'setbytes $f 806 0000000e' reject "name length field says 14"
	tcase T15.20 "$X" "payload byte flipped" 'flipbyte $f 900' reject "HMAC verification failed"
	tcase T15.21 "$X" "end record cut" 'truncate -s -4 $f' reject "HMAC verification failed"
	tcase T15.22 "$X" "1 byte appended" 'printf x >>$f' reject "HMAC verification failed"
	tcase T15.23 "$A" "AES: unused nonce byte flipped" 'flipbyte $f 74' reject "unused nonce bytes"
	tcase T15.24 "$A" "AES: cipher 0x01 -> 0x02" 'setbytes $f 8 02' reject "decrypt filename"
}

t16() {
	section "T16 crafted names (valid HMAC)"
	local h=$WORK/t16/home name i=0; mkdir -p "$h/Downloads"
	printf 'echo "this line came out of invoice.cm"\n' >"$WORK/t16/payload"
	for name in '../../.bashrc' '../.profile' '..' '.' '/tmp/abs-name' 'sub/dir.txt'; do
		i=$((i + 1)); printf 'original\n' >"$h/.bashrc"
		rm -f "$h/Downloads/$i.cm"; "$CRAFT" craft -in "$WORK/t16/payload" -out "$h/Downloads/$i.cm" -password "$PW" -name "$name"
		cm --decrypt --file "$h/Downloads/$i.cm" --password "$PW" --no-progress
		[[ $RC -eq 1 ]] && has "not a plain file name" && grep -q original "$h/.bashrc" && [[ $(count "$h/Downloads/decrypted") -eq 0 ]] &&
			pass T16.$i "stored name '$name' refused, nothing written" || fail T16.$i "'$name': rc=$RC $(errline)"
	done
	rm -f "$h/Downloads"/*.cm; "$CRAFT" craft -in "$WORK/t16/payload" -out "$h/Downloads/invoice.cm" -password "$PW" -name '../../.bashrc'
	cm --decrypt --folder "$h/Downloads" --password "$PW" --no-progress
	[[ $RC -eq 1 ]] && grep -q original "$h/.bashrc" && pass T16.7 "same through --folder: rc=1" || fail T16.7 "rc=$RC"
	local esc=$'\e]0;TITLE-SET-BY-FILE\a\e[2K\rnice.txt'
	"$CRAFT" craft -in "$WORK/t16/payload" -out "$WORK/t16/esc.cm" -password "$PW" -name "$esc"
	cm --decrypt --file "$WORK/t16/esc.cm" --password "$PW" --no-progress
	[[ $RC -eq 0 ]] && ! grep -aq $'\e' "$ERR" && has '\x1b]0;TITLE-SET-BY-FILE\x07' && pass T16.8 "escape sequences in a name are printed escaped" || fail T16.8 "rc=$RC"
}

t17() {
	section "T17 crafted stream framing (valid HMAC)"
	local d=$WORK/t17; mkdir -p "$d"; head -c 3000 /dev/urandom >"$d/p"
	"$CRAFT" craft -in "$d/p" -out "$d/huge.cm" -password "$PW" -name p -chunklen 4294967295
	cm --decrypt --file "$d/huge.cm" --password "$PW" --no-progress
	[[ $RC -eq 1 ]] && has "malformed encrypted stream" && [[ $(count "$d/decrypted") -eq 0 ]] && pass T17.1 "chunk length 0xffffffff: rc=1, nothing left" || fail T17.1 "rc=$RC $(errline)"
	"$CRAFT" craft -in "$d/p" -out "$d/short.cm" -password "$PW" -name p -chunklen 100
	rm -rf "$d/decrypted"; cm --decrypt --file "$d/short.cm" --password "$PW" --no-progress
	[[ $RC -eq 1 && $(count "$d/decrypted") -eq 0 ]] && pass T17.2 "wrong chunk length: rc=1" || fail T17.2 "rc=$RC"
	"$CRAFT" craft -in "$d/p" -out "$d/nosent.cm" -password "$PW" -name p -nosentinel
	rm -rf "$d/decrypted"; cm --decrypt --file "$d/nosent.cm" --password "$PW" --no-progress
	[[ $RC -eq 1 ]] && has "missing end-of-stream record" && pass T17.3 "missing end record: rc=1" || fail T17.3 "rc=$RC $(errline)"
	"$CRAFT" craft -in "$d/p" -out "$d/badhash.cm" -password "$PW" -name p -badhash
	rm -rf "$d/decrypted"; cm --decrypt --file "$d/badhash.cm" --password "$PW" --no-progress
	[[ $RC -eq 1 ]] && has "hash does not match" && [[ $(count "$d/decrypted") -eq 0 ]] && pass T17.4 "wrong stored SHA-512: rc=1, temp removed" || fail T17.4 "rc=$RC"
}

t18() {
	section "T18 --analyze"
	local d=$WORK/t18 nm=quarterly-salaries-2026.xlsx; mkdir -p "$d"; printf 'x%.0s' {1..50} >"$d/$nm"
	cm --encrypt --file "$d/$nm" --password "$PW" "${LM[@]}"; local enc; enc=$(only "$d/encrypted")
	cm --analyze --file "$enc"
	[[ $RC -eq 0 ]] && has "Key derivation: Argon2id 64 MiB" && ! has "name" && pass T18.1 "analyze: KDF shown, name length not shown" || fail T18.1 "rc=$RC"
	cm --analyze --file "$enc" --debug
	[[ $RC -eq 0 ]] && has "Padded name len: 496" && has "KDF mode:        0x01" && pass T18.2 "--analyze --debug dumps the header" || fail T18.2 "rc=$RC"
	printf 'CRYPTv2\0' >"$d/v2"; head -c 900 /dev/zero >>"$d/v2"
	cm --analyze --file "$d/v2"; [[ $RC -eq 1 ]] && has "v2 format" && pass T18.3 "v2 file refused" || fail T18.3 "rc=$RC"
	head -c 900 /dev/urandom >"$d/rnd"; cm --analyze --file "$d/rnd"; [[ $RC -eq 1 ]] && has "invalid file signature" && pass T18.4 "random file refused" || fail T18.4 "rc=$RC"
	head -c 100 "$enc" >"$d/short"; cm --analyze --file "$d/short"; [[ $RC -eq 1 ]] && has "shorter than system block" && pass T18.5 "short file refused" || fail T18.5 "rc=$RC"
	head -c 810 "$enc" >"$d/hdronly"; cm --decrypt --file "$d/hdronly" --password "$PW" --no-progress
	[[ $RC -eq 1 ]] && has "HMAC" && pass T18.6 "header-only file: HMAC error" || fail T18.6 "rc=$RC $(errline)"
}

t19() {
	section "T19 --debug, --trace, --log"
	local d=$WORK/t19; mkdir -p "$d"; printf 'debug test data\n' >"$d/f.txt"
	cm --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}" --debug
	[[ $RC -eq 0 ]] && has "Argon2id key derivation" && ! has "Derived key" && ! has "$PW" &&
		pass T19.1 "--debug: header data, no key, no password" || fail T19.1 "rc=$RC"
	rm -rf "$d/encrypted"
	cm --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}" --trace --log "$d/logs/trace.log"
	local enc; enc=$(only "$d/encrypted")
	if [[ $RC -eq 0 ]] && grep -qE 'msg="Derived key" key=[0-9a-f]{64}' "$ERR" && has "password=$PW" && has "file_sha512=" &&
		has "--trace prints the password" && grep -q 'Derived key' "$d/logs/trace.log" && [[ $(stat -c %a "$d/logs/trace.log") == 600 ]]; then
		pass T19.2 "--trace: password, key, plaintext hash; warning; log file 600"
	else fail T19.2 "rc=$RC"; fi
	cm --decrypt --file "$enc" --password "$PW" --no-progress --trace
	[[ $RC -eq 0 ]] && has "Decrypted chunk" && has "original_name=f.txt" && pass T19.3 "--trace on decrypt: chunks, name, hashes" || fail T19.3 "rc=$RC"
	cm --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}" --verbose --log "$d/logs/run.log"
	grep -q 'msg="Encrypted ' "$d/logs/run.log" && ! grep -q 'Derived key' "$d/logs/run.log" &&
		pass T19.4 "--log without --debug keeps the messages" || fail T19.4 "log: $(head -c 200 "$d/logs/run.log")"
	grep -aq $'\e\\[' "$ERR" && fail T19.5 "colour codes written to a non-terminal" || pass T19.5 "no colour codes when stderr is not a terminal"
}

t20() {
	section "T20 interrupted runs (SIGTERM; SIGINT is covered by T23)"
	local free; free=$(df -m --output=avail "$WORK" | tail -1 | tr -d ' ')
	((free >= 450)) || { pass T20 "skipped: only ${free} MB free"; return; }
	local d=$WORK/t20; rm -rf "$d"; mkdir -p "$d"; truncate -s $((129 * 1024 * 1024)) "$d/big.bin"
	(ulimit -v "$VLIMIT"; exec "$BIN" --encrypt --file "$d/big.bin" --password "$PW" "${LM[@]}") >/dev/null 2>"$ERR" &
	local pid=$! i
	for i in $(seq 1 1000); do compgen -G "$d/encrypted/*" >/dev/null && break; sleep 0.01; done
	sleep 0.2; kill -TERM "$pid" 2>/dev/null; wait "$pid"; local rc=$?
	if [[ $rc -eq 143 && $(count "$d/encrypted") -eq 0 ]] && grep -aq "removed 1 partial file" "$ERR"; then pass T20.1 "encryption: rc=143, partial file removed"
	elif [[ $rc -eq 0 ]]; then pass T20.1 "inconclusive: finished before the signal"
	else fail T20.1 "rc=$rc, $(count "$d/encrypted") files left"; fi
	rm -rf "$d/encrypted"; cm --encrypt --file "$d/big.bin" --password "$PW" "${LM[@]}"; local enc; enc=$(only "$d/encrypted"); rm -f "$d/big.bin"
	(ulimit -v "$VLIMIT"; exec "$BIN" --decrypt --file "$enc" --password "$PW" --no-progress) >/dev/null 2>"$ERR" &
	pid=$!; local tmp=
	for i in $(seq 1 3000); do
		tmp=$(compgen -G "$d/encrypted/decrypted/*.tmp" | head -1)
		[[ -n $tmp && -s $tmp ]] && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.01
	done
	kill -TERM "$pid" 2>/dev/null; wait "$pid"; rc=$?
	if [[ $rc -eq 143 && $(count "$d/encrypted/decrypted") -eq 0 ]]; then pass T20.2 "decryption: rc=143, temp file with plaintext removed"
	elif [[ $rc -eq 0 ]]; then pass T20.2 "inconclusive: finished before the signal"
	else fail T20.2 "rc=$rc, $(count "$d/encrypted/decrypted") files left"; fi
	rm -rf "$d"
}

t21() {
	section "T21 Argon2id cost recorded in the file (free RAM: $AVAIL_MB MiB)"
	local d=$WORK/t21; mkdir -p "$d"; printf 'kdf mode test\n' >"$d/f.txt"
	cm --encrypt --file "$d/f.txt" --password "$PW" --no-progress; local enc; enc=$(only "$d/encrypted")
	if ((BIG)); then
		[[ $RC -eq 0 && $(hexat "$enc" 9 1) == 02 ]] && pass T21.1 "default run on a big machine records 4 GiB (0x02)" || fail T21.1 "rc=$RC kdf=$(hexat "$enc" 9 1)"
	else
		[[ $RC -eq 0 && $(hexat "$enc" 9 1) == 01 ]] && has "using Argon2id with 64 MiB instead of 4 GiB" &&
			pass T21.1 "less than 8 GiB free: falls back to 64 MiB, warns, records 0x01" || fail T21.1 "rc=$RC kdf=$(hexat "$enc" 9 1)"
	fi
	cm --decrypt --file "$enc" --password "$PW" --no-progress
	[[ $RC -eq 0 ]] && cmp -s "$d/f.txt" "$d/encrypted/decrypted/f.txt" && pass T21.2 "decrypts without any flag" || fail T21.2 "rc=$RC $(errline)"
	if ! ((BIG)); then
		cp "$enc" "$d/std.cm"; setbytes "$d/std.cm" 9 02
		cm --decrypt --file "$d/std.cm" --password "$PW" --no-progress
		[[ $RC -eq 1 ]] && has "not enough free memory" && pass T21.3 "4 GiB file on a small machine: refused before deriving" || fail T21.3 "rc=$RC $(errline)"
	fi
}

t22() {
	section "T22 progress bars only on a terminal"
	local d=$WORK/t22; mkdir -p "$d"; head -c $((12 * 1024 * 1024)) /dev/urandom >"$d/f.bin"
	cm --encrypt --file "$d/f.bin" --password "$PW" --low-memory
	[[ $RC -eq 0 ]] && ! grep -aq $'\r' "$ERR" && pass T22.1 "no progress frames when stderr is redirected" || fail T22.1 "rc=$RC"
	rm -rf "$d/encrypted"
	script -q -e -c "bash -c 'ulimit -v $VLIMIT; exec \"$BIN\" --encrypt --file \"$d/f.bin\" --password \"$PW\" --low-memory'" /dev/null >"$OUT" 2>&1; RC=$?
	[[ $RC -eq 0 ]] && grep -aq 'Encrypting \[' "$OUT" && pass T22.2 "progress bar on a terminal (pty)" || fail T22.2 "rc=$RC"
}

t23() {
	section "T23 Ctrl+C at the password prompt (real pty)"
	local d=$WORK/t23; mkdir -p "$d"; printf 'pty test\n' >"$d/f.txt"
	local r; r=$(python3 -I "$HERE/pty_sigint.py" "$BIN" "$d/f.txt" 2>&1)
	[[ $r == *"echo_during=False echo_after=True child=exit 130"* ]] && pass T23 "echo restored, exit 130 ($r)" || fail T23 "$r"
}

t24() {
	section "T24 write failures and read-only places"
	local d=$WORK/t24; mkdir -p "$d/w"; head -c $((3 * 1024 * 1024)) /dev/urandom >"$d/w/big.bin"
	(ulimit -v "$VLIMIT"; ulimit -f 1024; exec "$BIN" --encrypt --file "$d/w/big.bin" --password "$PW" "${LM[@]}") >"$OUT" 2>"$ERR"; RC=$?
	[[ $RC -eq 1 && $(count "$d/w/encrypted") -eq 0 ]] && pass T24.1 "write error while encrypting: rc=1, nothing left" || fail T24.1 "rc=$RC"
	cm --encrypt --file "$d/w/big.bin" --password "$PW" "${LM[@]}"; local enc; enc=$(only "$d/w/encrypted")
	(ulimit -v "$VLIMIT"; ulimit -f 1024; exec "$BIN" --decrypt --file "$enc" --password "$PW" --no-progress) >"$OUT" 2>"$ERR"; RC=$?
	[[ $RC -eq 1 && $(count "$d/w/encrypted/decrypted") -eq 0 ]] && pass T24.2 "write error while decrypting: rc=1, nothing left" || fail T24.2 "rc=$RC"
	mkdir -p "$d/ro"; printf 'readonly dir test' >"$d/ro/f.txt"; chmod 555 "$d/ro"
	local t0=$SECONDS; cm --encrypt --file "$d/ro/f.txt" --password "$PW" "${LM[@]}"; chmod 755 "$d/ro"
	[[ $RC -eq 1 ]] && has "create output dir" && pass T24.3 "read-only parent: rc=1 before the key derivation ($((SECONDS - t0))s)" || fail T24.3 "rc=$RC"
	mkdir -p "$d/e1/encrypted"; cp "$d/ro/f.txt" "$d/e1/"; chmod 555 "$d/e1/encrypted"
	cm --encrypt --file "$d/e1/f.txt" --password "$PW" "${LM[@]}"; chmod 755 "$d/e1/encrypted"
	[[ $RC -eq 1 ]] && has "create output:" && pass T24.4 "read-only encrypted/: rc=1" || fail T24.4 "rc=$RC"
	mkdir -p "$d/w/encrypted/decrypted"; chmod 555 "$d/w/encrypted/decrypted"
	cm --decrypt --file "$enc" --password "$PW" --no-progress; chmod 755 "$d/w/encrypted/decrypted"
	[[ $RC -eq 1 ]] && has "create temp" && pass T24.5 "read-only decrypted/: rc=1" || fail T24.5 "rc=$RC"
	mkdir -p "$d/locked"; printf 'x' >"$d/locked/a.txt"; chmod 000 "$d/locked"
	cm --encrypt --folder "$d/locked" --password "$PW" "${LM[@]}"; chmod 755 "$d/locked"
	[[ $RC -eq 1 ]] && has "read directory" && pass T24.6 "unreadable folder: rc=1" || fail T24.6 "rc=$RC"
	mkdir -p "$d/fold"; cp "$enc" "$d/fold/ok.cm"; cp "$enc" "$d/fold/locked.cm"; chmod 000 "$d/fold/locked.cm"
	cm --decrypt --folder "$d/fold" --password "$PW" --no-progress; chmod 600 "$d/fold/locked.cm"
	[[ $RC -eq 1 && $(summary) == "1 processed, 0 skipped, 1 failed" ]] && pass T24.7 "unreadable encrypted file counts as failed" || fail T24.7 "rc=$RC $(summary)"
}

t25() {
	section "T25 misc"
	local d=$WORK/t25; mkdir -p "$d"; printf 'same input\n' >"$d/f.txt"
	cm --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}"; cm --encrypt --file "$d/f.txt" --password "$PW" "${LM[@]}"
	local a b; a=$(compgen -G "$d/encrypted/*" | head -1); b=$(compgen -G "$d/encrypted/*" | tail -1)
	[[ $a != "$b" ]] && ! cmp -s "$a" "$b" && [[ $(hexat "$a" 10 64) != $(hexat "$b" 10 64) ]] && pass T25.1 "two encryptions differ" || fail T25.1 "equal"
	(cd "$d" && (ulimit -v "$VLIMIT"; exec "$BIN" --decrypt --file "encrypted/$(basename "$a")" --password "$PW" --aes --no-progress) >"$OUT" 2>"$ERR"); RC=$?
	[[ $RC -eq 0 ]] && cmp -s "$d/f.txt" "$d/encrypted/decrypted/f.txt" && has "read from each file" &&
		pass T25.2 "relative path; banner does not claim a cipher on decrypt" || fail T25.2 "rc=$RC"
}

# ---------------------------------------------------------------------------
log "cryptomotor e2e  $(date -u +%FT%TZ)  binary $BIN ($(sha256sum "$BIN" | cut -c1-16))"
log "workdir $WORK  umask $(umask)  free RAM ${AVAIL_MB} MiB  VLIMIT $VLIMIT  3.1.0: ${OLD:-none}"
for t in ${TESTS:-t01 t02 t03 t05 t06 t07 t08 t09 t10 t12 t13 t14 t15 t16 t17 t18 t19 t20 t21 t22 t23 t24 t25}; do
	"$t"
done
log ""
log "SUMMARY  pass=$npass fail=$nfail"
((nfail == 0))
