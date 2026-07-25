#!/usr/bin/env bash
set -u

bin=${1:-}
[[ -n ${bin} ]] || {
	echo 'usage: run.sh <path-to-envctl>' >&2
	exit 2
}
[[ ${bin} == /* || ${bin} == [A-Za-z]:* ]] || bin=${PWD}/${bin}
[[ -x ${bin} ]] || {
	echo "not executable: ${bin}" >&2
	exit 2
}
readonly bin

envctl() {
	"${bin}" "$@"
}

work=$(mktemp -d) || exit 2
trap 'cd /; rm -rf "${work}"' EXIT INT TERM
cd "${work}" || exit 2

declare -i passed=0
declare -a failures=()

group() {
	printf '\n%s\n' "$1"
}

ok() {
	((++passed))
	[[ -z ${V:-} ]] || printf '  ok    %s\n' "$1"
}

bad() {
	local name=$1 detail
	shift
	failures+=("${name}")
	printf '  FAIL  %s\n' "${name}"
	for detail in "$@"; do
		printf '        %s\n' "${detail}"
	done
}

eq() {
	local name=$1 want=$2 got rc
	shift 2
	got=$(eval "$*" 2>/dev/null)
	rc=$?
	if ((rc == 0)) && [[ ${got} == "${want}" ]]; then
		ok "${name}"
	else
		bad "${name}" "want [${want}] rc 0" "got  [${got}] rc ${rc}"
	fi
}

ck() {
	local name=$1
	shift
	if eval "$*" >/dev/null 2>&1; then
		ok "${name}"
	else
		bad "${name}" "expected success: $*"
	fi
}

nk() {
	local name=$1
	shift
	if eval "$*" >/dev/null 2>&1; then
		bad "${name}" "expected failure: $*"
	else
		ok "${name}"
	fi
}

repeat() {
	local -i n=$1 i
	local unit=$2 out=
	for ((i = 0; i < n; i++)); do
		out+=${unit}
	done
	printf '%s' "${out}"
}

group 'help'
ck 'short help lists the redact command' "envctl -h | grep -q 'redact'"
ck 'long help documents --no-env' "envctl --help | grep -q -- '--no-env'"
ck 'long help documents the diff format' "envctl --help | grep -q 'unified diff'"
ck 'short help does not force KEY onto every command' "envctl -h | grep -q '^usage: envctl <cmd> \[file\] \[args'"
ck 'long help notes redact rejects --raw' "envctl --help | grep -q 'redact rejects it'"

group 'basic get and redact flags'
printf 'FOO=one\nAPI_TOKEN=abcdefghij\nPASSWORD=short\n' >dotenv.test
eq 'plain value reads back' 'one' "envctl get dotenv.test FOO"
eq 'API_TOKEN masks' '<redacted>' "envctl --redact get dotenv.test API_TOKEN"
eq 'PASSWORD masks' '<redacted>' "envctl --redact get dotenv.test PASSWORD"
eq '--raw beats --redact' 'abcdefghij' "envctl --raw get dotenv.test API_TOKEN"
eq 'plain value survives --redact' 'one' "envctl --redact get dotenv.test FOO"

group 'dry-run diff'
envctl --dry-run set dotenv.test FOO two >r1.test 2>/dev/null
ck 'old-file header' "grep -q '^--- dotenv.test\$' r1.test"
ck 'new-file header' "grep -q '^+++ dotenv.test\$' r1.test"
ck 'hunk header for in-place edit' "grep -q '^@@ -1,1 +1,1 @@\$' r1.test"
ck 'removed line' "grep -q '^-FOO=one\$' r1.test"
ck 'added line' "grep -q '^+FOO=two\$' r1.test"
nk 'unrelated API_TOKEN absent' "grep -q 'API_TOKEN' r1.test"
nk 'unrelated PASSWORD absent' "grep -q 'PASSWORD' r1.test"
eq 'one-key change is 5 lines' '5' "grep -c '' r1.test"
envctl --dry-run --redact set dotenv.test API_TOKEN x >r2.test 2>/dev/null
ck 'redacted diff marks its header' "grep -q '^+++ dotenv.test (redacted)\$' r2.test"
ck 'old value masked' "grep -q '^-API_TOKEN=<redacted>\$' r2.test"
ck 'new value masked' "grep -q '^+API_TOKEN=<redacted>\$' r2.test"
nk 'old secret absent from redacted diff' "grep -q 'abcdefghij' r2.test"
nk 'unrelated FOO absent' "grep -q 'FOO' r2.test"
ck '--raw dry-run shows the old secret' "envctl --dry-run --raw set dotenv.test API_TOKEN x | grep -q '^-API_TOKEN=abcdefghij\$'"
ck 'no-op prints nothing on stdout' "test -z \"\$(envctl --dry-run set dotenv.test FOO one 2>/dev/null)\""
ck 'no-op reports on stderr' "envctl --dry-run set dotenv.test FOO one 2>&1 >/dev/null | grep -q 'no changes'"
envctl --dry-run delete dotenv.test PASSWORD >r3.test 2>/dev/null
ck 'delete hunk header' "grep -q '^@@ -3,1 +2,0 @@\$' r3.test"
ck 'deleted line shown' "grep -q '^-PASSWORD=short\$' r3.test"
eq 'delete adds only the +++ header' '1' "grep -c '^+' r3.test"
ck 'append shows the new line' "envctl --dry-run set dotenv.test NEWKEY v | grep -q '^+NEWKEY=v\$'"
ck 'append hunk header' "envctl --dry-run set dotenv.test NEWKEY v | grep -q '^@@ -3,0 +4,1 @@\$'"
: >empty.test
ck 'insert into empty file' "envctl --dry-run set empty.test A 1 | grep -q '^@@ -0,0 +1,1 @@\$'"
eq 'dry-run wrote nothing' '3' "grep -c '' dotenv.test"
envctl set dotenv.test FOO two
eq 'set persists' 'two' "envctl get dotenv.test FOO"

group 'value detectors'
cat >d1.test <<'FIXTURE'
FOO_AUTH=deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef
AUTH_TOK=qxvbnmzlkjhgfdsapoiuytrewqasdfgh
GH="ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"
JW="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
AUTHZ=Bearer abcdefghijklmnopqrstuvwxyz012345
BASICH=Basic dXNlcjpwYXNzd29yZDEyMw==
SCHEME=Bearer
CB=https://api.example.com/v1?token=abcdef1234567890
S3=https://b.s3.amazonaws.com/k?X-Amz-Signature=abcdef1234567890
PLAINURL=https://api.example.com/v1/health
WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/XXXXXXXXXXXXXXXXXXXXXXXX
JWK={"kty":"EC","crv":"P-256","x":"aa","d":"ccccccccccccccccc"}
PUBJWK={"kty":"EC","crv":"P-256","x":"aa","y":"bb"}
CONN=Server=db;Database=app;Pwd=Sup3rSecret99;
AWSK=A3TXABCDEFGHIJKLMNOP
PUTTY=PuTTY-User-Key-File-3: ssh-rsa
SESSION_ID=abcdef0123456789abcdef0123456789
GIT_AUTH_SHA=da39a3ee5e6b4b0d3255bfef95601890afd80709
API_KEY_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
BUILD_UUID=550e8400-e29b-41d4-a716-446655440000
AUTH_URL=https://example.com/some/long/path/to/a/resource/index.html
CRED_PATH=/run/secrets/gcp-service-account-key.json
CONFIG_JSON={"api_token":"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB","x":1}
PG_CONN=host=db port=5432 user=app password=Sup3rSecret99
CLI_ARGS=--verbose --out /tmp/build.log --retries 3
JAVA_OPTS=-Dspring.datasource.password=Sup3rSecret99x
NPM_CONFIG=//registry.npmjs.org/:_authToken=npm_0123456789abcdefghijABCDEFGHIJ012345
EXTRA_ARGS=--password=Sup3rS3cretHunter2Value --verbose
OPTS_ARGS=--output=report.txt --retries 3
SLACK_WEBHOOK_ENDPOINT=https://hooks.slack.com/services/T0/B0/XXXXXXXXXXXXXXXXXXXXXXXX
DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/aBcDeFgHiJkLmNoPqRs
WEBHOOK_ID=123456789012345678
PASSWORD_ID=hunter2hunter2
SECRET_ID=s3cr3tSessionSigningValue123456
VAULT_SECRET_ID=hvs.CAESIJk3xY2zQwErTyUiOpAsDfGhJkLzXcVbNm1234567890
API_TOKEN_NAME=s3cr3tSessionSigningValue123456
CLIENT_SECRET_VERSION=s3cr3tSessionSigningValue123456
APP_SECRET_VERSION=3
OAUTH_CLIENT_ID=1234567890-abcdefghijklmnop.apps.googleusercontent.com
GPG_PASSPHRASE_FILE=/run/secrets/gpg.txt
GPG_PASSPHRASE=s3cr3tSessionSigningValue123456
BACKUP_PASSPHRASE_FILE=s3cr3tSessionSigningValue123456
LICENSE_KEY=qxvbnmzlkjhgfdsapoiuytrewqasdfgh
IDEMPOTENCY_KEY=aB3xY7zQ9wErTyUiOpAsDfGhJkLz
KEYBOARD_LAYOUT=us
MONKEY_NAME=george
API_VERSION=v2
FIXTURE
{
	printf 'LONG_AUTH='
	repeat 100 'aB3xY7zQ9wErTyUiOpAsDfGhJkLzXcVb0123456789abcdefghij'
	printf '\n'
} >>d1.test

eq 'hex-only high entropy under AUTH' '<redacted>' "envctl --redact get d1.test FOO_AUTH"
eq 'lowercase-only high entropy under AUTH' '<redacted>' "envctl --redact get d1.test AUTH_TOK"
eq 'quoted github token' '<redacted>' "envctl --redact get d1.test GH"
eq 'quoted jwt' '<redacted>' "envctl --redact get d1.test JW"
eq 'Bearer value' '<redacted>' "envctl --redact get d1.test AUTHZ"
eq 'Basic value' '<redacted>' "envctl --redact get d1.test BASICH"
eq 'bare scheme word is not a credential' 'Bearer' "envctl --redact get d1.test SCHEME"
eq 'url token= parameter' '<redacted:credentials>' "envctl --redact get d1.test CB"
eq 'url X-Amz-Signature parameter' '<redacted:credentials>' "envctl --redact get d1.test S3"
eq 'plain url untouched' 'https://api.example.com/v1/health' "envctl --redact get d1.test PLAINURL"
eq 'webhook url' '<redacted>' "envctl --redact get d1.test WEBHOOK_URL"
eq 'private jwk' '<redacted:private-key>' "envctl --redact get d1.test JWK"
ck 'public jwk untouched' "envctl --redact get d1.test PUBJWK | grep -q '^{\"kty\"'"
eq 'connection string password' '<redacted:credentials>' "envctl --redact get d1.test CONN"
eq 'aws A3T key id' '<redacted>' "envctl --redact get d1.test AWSK"
eq 'putty key header' '<redacted:private-key>' "envctl --redact get d1.test PUTTY"
eq 'session id kept' 'abcdef0123456789abcdef0123456789' "envctl --redact get d1.test SESSION_ID"
eq 'git sha kept' 'da39a3ee5e6b4b0d3255bfef95601890afd80709' "envctl --redact get d1.test GIT_AUTH_SHA"
eq 'sha256 digest kept' 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' "envctl --redact get d1.test API_KEY_SHA256"
eq 'uuid kept' '550e8400-e29b-41d4-a716-446655440000' "envctl --redact get d1.test BUILD_UUID"
ck 'long path url kept' "envctl --redact get d1.test AUTH_URL | grep -q '^https://example.com/some'"
eq 'credential path kept' '/run/secrets/gcp-service-account-key.json' "envctl --redact get d1.test CRED_PATH"
eq 'token embedded in json' '<redacted>' "envctl --redact get d1.test CONFIG_JSON"
eq 'libpq connection string' '<redacted>' "envctl --redact get d1.test PG_CONN"
ck 'plain cli args kept' "envctl --redact get d1.test CLI_ARGS | grep -q '^--verbose --out /tmp/build.log --retries 3\$'"
eq 'java -D password property' '<redacted>' "envctl --redact get d1.test JAVA_OPTS"
eq 'npmrc authToken' '<redacted>' "envctl --redact get d1.test NPM_CONFIG"
eq '--password= in an argument list' '<redacted>' "envctl --redact get d1.test EXTRA_ARGS"
ck '--output= in an argument list kept' "envctl --redact get d1.test OPTS_ARGS | grep -q '^--output=report.txt --retries 3\$'"
nk 'embedded token absent from list --values' "envctl --redact list d1.test --values | grep -q 'ghp_0123'"
ck '--raw still returns the embedded token' "envctl --raw get d1.test CONFIG_JSON | grep -q 'ghp_0123'"
eq 'webhook endpoint suffix' '<redacted>' "envctl --redact get d1.test SLACK_WEBHOOK_ENDPOINT"
eq 'discord webhook' '<redacted>' "envctl --redact get d1.test DISCORD_WEBHOOK"
eq 'webhook id kept' '123456789012345678' "envctl --redact get d1.test WEBHOOK_ID"
eq 'PASSWORD_ID masks' '<redacted>' "envctl --redact get d1.test PASSWORD_ID"
eq 'SECRET_ID masks' '<redacted>' "envctl --redact get d1.test SECRET_ID"
eq 'vault secret id' '<redacted>' "envctl --redact get d1.test VAULT_SECRET_ID"
eq 'API_TOKEN_NAME masks' '<redacted>' "envctl --redact get d1.test API_TOKEN_NAME"
eq 'CLIENT_SECRET_VERSION masks' '<redacted>' "envctl --redact get d1.test CLIENT_SECRET_VERSION"
eq 'low entropy version number kept' '3' "envctl --redact get d1.test APP_SECRET_VERSION"
eq 'oauth client id kept' '1234567890-abcdefghijklmnop.apps.googleusercontent.com' "envctl --redact get d1.test OAUTH_CLIENT_ID"
eq 'passphrase file path kept' '/run/secrets/gpg.txt' "envctl --redact get d1.test GPG_PASSPHRASE_FILE"
eq 'passphrase value masks' '<redacted>' "envctl --redact get d1.test GPG_PASSPHRASE"
eq '_FILE suffix with a secret value still masks' '<redacted>' "envctl --redact get d1.test BACKUP_PASSPHRASE_FILE"
eq 'KEY segment alone plus entropy' '<redacted>' "envctl --redact get d1.test LICENSE_KEY"
eq 'KEY segment alone plus mixed-case entropy' '<redacted>' "envctl --redact get d1.test IDEMPOTENCY_KEY"
eq 'KEYBOARD is not a KEY segment' 'us' "envctl --redact get d1.test KEYBOARD_LAYOUT"
eq 'MONKEY is not a KEY segment' 'george' "envctl --redact get d1.test MONKEY_NAME"
eq 'API_VERSION kept' 'v2' "envctl --redact get d1.test API_VERSION"
eq 'oversized value masks' '<redacted>' "envctl --redact get d1.test LONG_AUTH"
eq 'oversized value survives --raw intact' '5201' "envctl --raw get d1.test LONG_AUTH | wc -c | tr -d ' '"
eq 'quotes preserved by --raw' '"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"' "envctl --raw get d1.test GH"

group 'multiline spans'
cat >ml.test <<'FIXTURE'
FOO=bar
PK="-----BEGIN PRIVATE KEY-----
Zm9vYmFyYmF6cXV4c2VjcmV0ZGF0YQ==
MIIBIjANBgkq
-----END PRIVATE KEY-----"
AFTER=ok
FIXTURE
cp ml.test ml0.test
envctl --redact list ml.test --values >l1.test 2>/dev/null
ck 'span head masked' "grep -q '^PK=<redacted:private-key>\$' l1.test"
nk 'padded body line absent' "grep -q 'Zm9vYmFy' l1.test"
nk 'unpadded body line absent' "grep -q 'MIIBIjAN' l1.test"
ck 'key after the span still listed' "grep -q '^AFTER=ok\$' l1.test"
eq 'list --values yields 3 lines' '3' "grep -c '' l1.test"
eq 'list --values --raw is one record per key' '3' "envctl --raw list ml.test --values | grep -c ''"
nk 'list --values --raw omits continuation lines' "envctl --raw list ml.test --values | grep -q 'Zm9vYmFy'"
eq 'list without values yields 3 lines' '3' "envctl list ml.test | grep -c ''"
nk 'body absent from plain list' "envctl list ml.test | grep -q 'Zm9vYmFy'"
eq 'get masks the whole span' '<redacted:private-key>' "envctl --redact get ml.test PK"
eq 'raw get returns all 4 span lines' '4' "envctl --raw get ml.test PK | grep -c ''"
ck 'raw get includes the body' "envctl --raw get ml.test PK | grep -q 'Zm9vYmFy'"
cat >js.test <<'FIXTURE'
CRED_TOKEN="{
"type": "sa",
"client_secret": "s3cr3tvaluehere9x8y7z"
}"
TAIL=ok
FIXTURE
nk 'quoted json span body absent' "envctl --redact list js.test --values | grep -q 's3cr3tvaluehere'"
ck 'key after json span listed' "envctl --redact list js.test --values | grep -q '^TAIL=ok\$'"
cat >ml2.test <<'FIXTURE'
PK2="-----BEGIN PRIVATE KEY-----
-----END CERTIFICATE-----
Zm9vYmFyYmF6
-----END PRIVATE KEY-----"
TAIL2=ok
FIXTURE
nk 'mismatched END does not close the span' "envctl --redact list ml2.test --values | grep -q 'Zm9vYmFy'"
ck 'key after mismatched span listed' "envctl --redact list ml2.test --values | grep -q '^TAIL2=ok\$'"
cat >bare.test <<'FIXTURE'
FOO=1
-----BEGIN PRIVATE KEY-----
Zm9vYmFyYmF6cXV4
-----END PRIVATE KEY-----
SAFE=1
FIXTURE
eq 'unassigned pem block yields 2 keys' '2' "envctl --redact list bare.test --values | grep -c ''"
nk 'unassigned pem body absent' "envctl --redact list bare.test --values | grep -q 'Zm9vYmFy'"
envctl --redact --dry-run set bare.test SAFE 2 >r0.test 2>/dev/null
nk 'pem body absent from diff' "grep -q 'Zm9vYmFy' r0.test"
nk 'pem header absent from diff' "grep -q 'PRIVATE KEY' r0.test"
ck 'diff shows the removed line' "grep -q '^-SAFE=1\$' r0.test"
ck 'diff shows the added line' "grep -q '^+SAFE=2\$' r0.test"

group 'span-aware mutation'
ck 'dry-run did not touch the file' "cmp -s ml.test ml0.test"
envctl --raw --dry-run set ml.test PK new >r4.test 2>/dev/null
ck 'replacement line' "grep -q '^+PK=new\$' r4.test"
ck 'whole span shown as removed' "grep -q '^-Zm9vYmFyYmF6cXV4c2VjcmV0ZGF0YQ==\$' r4.test"
ck 'hunk spans 4 old lines' "grep -q '^@@ -2,4 +2,1 @@\$' r4.test"
nk 'line before the span absent' "grep -q '^.FOO=bar\$' r4.test"
nk 'line after the span absent' "grep -q '^.AFTER=ok\$' r4.test"
envctl --redact --dry-run set ml.test PK new >r5.test 2>/dev/null
nk 'redacted diff hides padded body' "grep -q 'Zm9vYmFy' r5.test"
nk 'redacted diff hides unpadded body' "grep -q 'MIIBIjAN' r5.test"
ck 'redacted diff masks the old span' "grep -q '^-PK=<redacted:private-key>\$' r5.test"
ck 'redacted diff shows the new value' "grep -q '^+PK=new\$' r5.test"
envctl --raw --dry-run delete ml.test PK >r6.test 2>/dev/null
ck 'delete hunk spans the whole span' "grep -q '^@@ -2,4 +1,0 @@\$' r6.test"
eq 'delete diff adds only the header' '1' "grep -c '^+' r6.test"
ck 'dry-runs left the file alone' "cmp -s ml.test ml0.test"
envctl --raw set ml.test PK newval
nk 'old body gone from disk' "grep -q 'Zm9vYmFy' ml.test"
nk 'old header gone from disk' "grep -q 'PRIVATE KEY' ml.test"
ck 'new value on disk' "grep -q '^PK=newval\$' ml.test"
ck 'preceding line intact' "grep -q '^FOO=bar\$' ml.test"
ck 'following line intact' "grep -q '^AFTER=ok\$' ml.test"
eq 'file is 3 lines after span replace' '3' "grep -c '' ml.test"
cp ml0.test ml.test
envctl --raw delete ml.test PK
nk 'delete removes the body too' "grep -q 'Zm9vYmFy' ml.test"
eq 'file is 2 lines after span delete' '2' "grep -c '' ml.test"
cp ml0.test ml.test
envctl --raw disable ml.test PK
eq 'disable comments every span line' '4' "grep -c '^# ' ml.test"
envctl --raw enable ml.test PK
ck 'enable restores the file byte for byte' "cmp -s ml.test ml0.test"

group 'byte preservation'
printf 'A=1\n\n#  spaced   comment\t\nB =  2  \nC=3\n' >pres.test
cp pres.test pres0.test
envctl set pres.test C 4
head -n 4 pres0.test >pres1.test
ck 'untouched lines unchanged' "head -n 4 pres.test | cmp -s - pres1.test"
printf 'A=1\nOOPS="no closing quote\nB=2\n' >unterm.test
cp unterm.test unterm0.test
nk 'delete refuses an unterminated span' "envctl --raw delete unterm.test OOPS 2>/dev/null"
ck 'refused delete wrote nothing' "cmp -s unterm.test unterm0.test"
nk 'set refuses an unterminated span' "envctl --raw set unterm.test OOPS x 2>/dev/null"
ck 'refused set wrote nothing' "cmp -s unterm.test unterm0.test"
ck 'agent env does not redact disk writes' "AI_AGENT=1 envctl set ml.test AFTER changed"
ck 'body still on disk after agent write' "grep -q 'Zm9vYmFy' ml.test"
ck 'header still on disk after agent write' "grep -q 'BEGIN PRIVATE KEY' ml.test"
nk 'no redaction token reached disk' "grep -q 'redacted' ml.test"

group 'quoting edge cases'
printf 'A=1\nMSG="hello" world\nB=2\nC=3\n' >q.test
eq 'trailing text after a closing quote does not swallow the file' '4' "envctl --raw list q.test | grep -c ''"
eq 'key after such a line reads back' '2' "envctl --raw get q.test B"
eq 'the quoted-plus-trailing value reads back whole' '"hello" world' "envctl --raw get q.test MSG"
envctl --raw set q.test B 9
eq 'set does not duplicate the key' '1' "grep -c '^B=' q.test"
eq 'set took effect' '9' "envctl --raw get q.test B"
envctl --raw delete q.test C
nk 'delete took effect' "envctl --raw get q.test C"
printf 'W="C:\\Users\\me\\"\nJSON={"a":1}\nLAST=1\n' >q2.test
eq 'windows path value does not swallow the file' '3' "envctl --raw list q2.test | grep -c ''"
printf 'ARGS="-x" --flag\nDEBUG=true\nSECRET=abc\n' >tail.test
eq 'quoted head with trailing args lists 3' '3' "envctl list tail.test | grep -c ''"
eq 'value after it reads back' 'true' "envctl get tail.test DEBUG"
envctl delete tail.test SECRET
nk 'deleted key gone' "grep -q '^SECRET=' tail.test"
ck 'quoted-plus-trailing line preserved' "grep -q '^ARGS=\"-x\" --flag\$' tail.test"
envctl set tail.test DEBUG false
eq 'set does not duplicate' '1' "grep -c '^DEBUG=' tail.test"
envctl set tail.test ARGS -y
ck 'quoted-plus-trailing line replaceable' "grep -q '^ARGS=-y\$' tail.test"
printf 'A="\nB=2\nC=3\n' >run.test
eq 'runaway quote does not hide later keys' '3' "envctl list run.test | grep -c ''"
envctl delete run.test C
ck 'runaway line preserved' "grep -q '^A=\"\$' run.test"
nk 'set refuses the runaway key' "envctl set run.test A x 2>/dev/null"
cat >sp1.test <<'FIXTURE'
KEY ="-----BEGIN PRIVATE KEY-----
Zm9vYmFyYmF6cXV4
-----END PRIVATE KEY-----"
TAIL=ok
FIXTURE
eq 'space before = still opens a span' 'TAIL=ok' "envctl --redact list sp1.test --values"
eq 'space before = span hidden from plain list' 'TAIL' "envctl --redact list sp1.test"
cat >sp2.test <<'FIXTURE'
MY-KEY="-----BEGIN PRIVATE KEY-----
Zm9vYmFyYmF6cXV4
-----END PRIVATE KEY-----"
TAIL=ok
FIXTURE
eq 'invalid key char still opens a span' 'TAIL=ok' "envctl --redact list sp2.test --values"
cat >sp3.test <<'FIXTURE'
2FA_KEY="-----BEGIN PRIVATE KEY-----
Zm9vYmFyYmF6cXV4
-----END PRIVATE KEY-----"
TAIL=ok
FIXTURE
eq 'leading digit still opens a span' 'TAIL=ok' "envctl --redact list sp3.test --values"
printf '# note: token = "abc\nREAL=1\n' >prose.test
ck 'a quote in prose does not open a span' "envctl --redact list prose.test --values --all | grep -q '^REAL=1\$'"
envctl --raw set sp1.test TAIL new
ck 'set after a lenient span works' "grep -q '^TAIL=new\$' sp1.test"
ck 'lenient span body untouched' "grep -q '^Zm9vYmFyYmF6cXV4\$' sp1.test"
eq 'lenient span file length unchanged' '4' "grep -c '' sp1.test"

group 'long keys'
k=$(repeat 290 A)_PASSWORD
printf '%s=hunter2secretvalue\n' "${k}" >lk.test
eq 'long key masks on get' '<redacted>' "envctl --redact get lk.test ${k}"
ck 'long key masks in list' "envctl --redact list lk.test --values | grep -q '=<redacted>\$'"
nk 'long key secret absent from list' "envctl --redact list lk.test --values | grep -q 'hunter2secretvalue'"
nk 'long key secret absent from diff' "envctl --redact --dry-run set lk.test ${k} newval | grep -q 'hunter2secretvalue'"
ck 'long key value enters the filter mask set' "printf 'x hunter2secretvalue y\n' | envctl redact lk.test | grep -q '^x <redacted> y\$'"

group 'filter literal masking'
cat >f1.test <<'FIXTURE'
API_TOKEN=s3cr3t-value-abcdefghij
DB_PASSWORD=p@ss/w0rd+x=y
Q_SECRET=p@ss"w0rd-1234
PORT=3000
DEBUG=true
APP_NAME=checkout
API_KEY=changeme
ADMIN_PASSWORD=staging
FOO=one
FIXTURE
ck 'literal value scrubbed' "echo 'leaked s3cr3t-value-abcdefghij here' | envctl redact f1.test | grep -q '^leaked <redacted> here\$'"
ck 'base64 variant scrubbed' "echo 'b64 czNjcjN0LXZhbHVlLWFiY2RlZmdoaWo=' | envctl redact f1.test | grep -q '^b64 <redacted>\$'"
echo 'emb WFhYczNjcjN0LXZhbHVlLWFiY2RlZmdoaWpZWVk=' | envctl redact f1.test >f3.test 2>/dev/null
nk 'shifted base64 phase scrubbed' "grep -q 'czNjcjN0LXZhbHVl' f3.test"
ck 'shifted base64 leaves a token' "grep -q '<redacted>' f3.test"
ck 'url-encoded variant scrubbed' "echo 'url p%40ss%2Fw0rd%2Bx%3Dy' | envctl redact f1.test | grep -q '^url <redacted>\$'"
ck 'json-escaped variant scrubbed' "printf '%s\n' 'json {\"pw\": \"p@ss\\\"w0rd-1234\"}' | envctl redact f1.test | grep -q '^json {\"pw\": \"<redacted>\"}\$'"
ck 'short numeric value does not scrub prose' "echo 'port 3000 stays' | envctl redact f1.test | grep -q '^port 3000 stays\$'"
printf 'debug true for checkout, changeme in staging, one more\n' >f4.test
ck 'trivial env values do not scrub prose' "envctl redact f1.test < f4.test | cmp -s - f4.test"
ck 'key names are not scrubbed' "echo 'plain one FOO API_TOKEN' | envctl redact f1.test | grep -q '^plain one FOO API_TOKEN\$'"
cat >f10.test <<'FIXTURE'
ML_TOKEN="line1secretvalueAAA
line2secretvalueBBB"
FIXTURE
printf 'a line1secretvalueAAA b\nc line2secretvalueBBB d\n' | envctl redact f10.test >f11.test 2>/dev/null
nk 'multiline value scrubbed per physical line' "grep -q 'secretvalue' f11.test"
eq 'both lines masked' '2' "grep -c '<redacted>' f11.test"
printf 'x\n-----BEGIN PRIVATE KEY-----\nQUJDREVGdGhpc2lzYW5vdGhlcmtleQ==\n-----END PRIVATE KEY-----\ny\n' | envctl redact ml.test >f12.test 2>/dev/null
nk 'pem in piped text scrubbed with an env file' "grep -q 'QUJDREVG' f12.test"
ck 'text after the pem preserved' "grep -q '^y\$' f12.test"

group 'filter heuristics'
ck 'github token' "echo 'tok ghp_0123456789abcdefghijklmnopqrstuvwxyzAB' | envctl redact --no-env | grep -q '^tok <redacted>\$'"
ck 'aws access key id' "echo 'aws AKIAIOSFODNN7EXAMPLE here' | envctl redact --no-env | grep -q '^aws <redacted> here\$'"
ck 'jwt' "echo 'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop end' | envctl redact --no-env | grep -q '^jwt <redacted> end\$'"
ck 'credentialed url' "echo 'DATABASE_URL=postgres://u:p@h/db' | envctl redact --no-env | grep -q '^DATABASE_URL=<redacted:credentials>\$'"
ck 'authorization header' "echo 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345' | envctl redact --no-env | grep -q '^Authorization: <redacted>\$'"
ck 'git sha kept' "echo 'sha da39a3ee5e6b4b0d3255bfef95601890afd80709 kept' | envctl redact --no-env | grep -q 'da39a3ee'"
ck 'uuid kept' "echo 'uuid 550e8400-e29b-41d4-a716-446655440000 kept' | envctl redact --no-env | grep -q '550e8400'"
ck 'bare prefix in prose kept' "echo 'prefix ghp_ named in prose' | envctl redact --no-env | grep -q '^prefix ghp_ named in prose\$'"
printf 'x\n-----BEGIN PRIVATE KEY-----\nZm9vYmFyYmF6cXV4\n-----END PRIVATE KEY-----\ny\n' | envctl redact --no-env >f2.test 2>/dev/null
nk 'pem body scrubbed' "grep -q 'Zm9vYmFy' f2.test"
ck 'pem collapses to one token' "grep -q '<redacted:private-key>' f2.test"
ck 'text after the pem preserved' "grep -q '^y\$' f2.test"
eq 'pem block collapses to a single line' '3' "grep -c '' f2.test"

group 'filter assignment shapes'
ck 'export prefix' "printf 'export DB_PASSWORD=Sup3rS3cretHunter2Value\n' | envctl redact --no-env | grep -q '^export DB_PASSWORD=<redacted>\$'"
ck 'diff plus prefix' "printf '+ DB_PASSWORD=Sup3rS3cretHunter2Value\n' | envctl redact --no-env | grep -q '^+ DB_PASSWORD=<redacted>\$'"
ck 'env prefix' "printf 'env DB_PASSWORD=Sup3rS3cretHunter2Value ./run.sh\n' | envctl redact --no-env | grep -q '^env DB_PASSWORD=<redacted> ./run.sh\$'"
ck 'docker -e flag' "printf 'docker run -e DB_PASSWORD=Sup3rS3cretHunter2Value img\n' | envctl redact --no-env | grep -q '^docker run -e DB_PASSWORD=<redacted> img\$'"
ck 'declare -x' "printf 'declare -x DB_PASSWORD=\"Sup3rS3cretHunter2Value\"\n' | envctl redact --no-env | grep -q '^declare -x DB_PASSWORD=\"<redacted>\"\$'"
ck 'diff minus prefix' "printf -- '- DB_PASSWORD=Sup3rS3cretHunter2Value\n' | envctl redact --no-env | grep -q '^- DB_PASSWORD=<redacted>\$'"
ck 'path value under a key name kept' "printf 'export KEY_PATH=/etc/ssl/private/server.pem\n' | envctl redact --no-env | grep -q '^export KEY_PATH=/etc/ssl/private/server.pem\$'"
ck 'innocent assignment kept' "printf 'export APP_NAME=checkout\n' | envctl redact --no-env | grep -q '^export APP_NAME=checkout\$'"
ck 'command prefix assignment kept' "printf 'NODE_ENV=production npm run build\n' | envctl redact --no-env | grep -q '^NODE_ENV=production npm run build\$'"
ck 'make variable kept' "printf 'make CFLAGS=-O2 all\n' | envctl redact --no-env | grep -q '^make CFLAGS=-O2 all\$'"
ck 'c source line kept' "printf 'int max_retries = 5;\n' | envctl redact --no-env | grep -q '^int max_retries = 5;\$'"
ck 'embedded -D password property' "printf 'JAVA_OPTS=-Dspring.datasource.password=Sup3rSecret99x\n' | envctl redact --no-env | grep -q '^JAVA_OPTS=<redacted>\$'"
ck 'output flag kept' "printf 'a --output=report.txt b\n' | envctl redact --no-env | grep -q '^a --output=report.txt b\$'"
ck 'git format string kept' "printf 'git log --format=%%H\n' | envctl redact --no-env | grep -q '^git log --format=%H\$'"
ck 'innocent query parameters kept' "printf 'curl \"https://x/y?page=2&sort=asc\"\n' | envctl redact --no-env | grep -q 'page=2&sort=asc'"
printf 'a\nerror: expected -----BEGIN OPENSSH PRIVATE KEY----- header\nb\nc\n' | envctl redact --no-env >f13.test 2>/dev/null
ck 'mid-line pem header masks its line' "grep -q '<redacted:private-key>' f13.test"
ck 'prose after it survives' "grep -q '^b\$' f13.test"
ck 'more prose after it survives' "grep -q '^c\$' f13.test"
eq 'no lines swallowed by a prose mention' '4' "grep -c '' f13.test"
printf 'ts | -----BEGIN RSA PRIVATE KEY-----\nts | MIIEowIBAAKCAQEA\nts | -----END RSA PRIVATE KEY-----\nafter\n' | envctl redact --no-env >f14.test 2>/dev/null
nk 'log-prefixed pem body scrubbed' "grep -q 'MIIEow' f14.test"
ck 'line after a log-prefixed pem survives' "grep -q '^after\$' f14.test"

group 'filter carry bounds'
printf -- '-----BEGIN PRIVATE KEY-----\n' >bigpem.test
for ((i = 1; i <= 600; i++)); do
	echo "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA${i}"
done >>bigpem.test
printf -- '-----END PRIVATE KEY-----\n' >>bigpem.test
nk 'oversized pem body fully scrubbed' "envctl redact --no-env < bigpem.test | grep -q 'MIIEvQ'"
eq 'oversized pem collapses to one line' '1' "envctl redact --no-env < bigpem.test | grep -c ''"
printf 'head\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\ntail\n' >f5.test
printf 'head\n-----BEGIN RSA PRIVATE KEY-----\n' >f6.test
{
	repeat 600 $'AAAA\n'
	printf 'tail\n'
} >>f6.test
ck 'carry releases at the cap' "envctl redact --no-env < f6.test | grep -q '^tail\$'"
nk 'unterminated pem suppresses to EOF below the cap' "envctl redact --no-env < f5.test | grep -q '^tail\$'"

group 'filter argument validation'
nk '--raw rejected' "echo x | envctl redact --raw f1.test"
nk 'missing file rejected' "echo x | envctl redact NOSUCHFILE"
nk '--no-env with a file rejected' "echo x | envctl redact --no-env f1.test"
nk '--no-env rejected outside redact' "envctl --no-env get f1.test FOO"

group 'filter byte fidelity'
ck 'line order and count preserved' "printf 'a\nb\n' | envctl redact --no-env | tr -d '\r' | tr '\n' ',' | grep -q '^a,b,\$'"
printf 'no trailing newline' >f7.test
ck 'missing trailing newline preserved' "envctl redact --no-env < f7.test | cmp -s - f7.test"
printf 'a\r\nb\r\n' >f8.test
ck 'crlf preserved' "envctl redact --no-env < f8.test | cmp -s - f8.test"
printf 'API_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\r\n' >f8s.test
printf 'API_TOKEN=<redacted>\r\n' >f8s.want
ck 'crlf preserved while masking' "envctl redact --no-env < f8s.test | cmp -s - f8s.want"

group 'command word collisions'
eq 'plain key after filter fixtures' 'one' "envctl get f1.test FOO"
eq 'numeric value after filter fixtures' '3000' "envctl get f1.test PORT"
printf 'redact=kept\n' >f9.test
eq 'a key named redact is still a key' 'kept' "envctl get f9.test redact"

group 'pem boundaries in filter mode'
printf -- '-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUA==\n-----END PRIVATE KEY----- API_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n' >pb1.test
envctl redact --no-env <pb1.test >pb1.out
nk 'secret after END line scrubbed' "grep -q 'ghp_0123' pb1.out"
ck 'assignment after END still keyed' "grep -q 'API_TOKEN=<redacted>' pb1.out"
printf -- '-----BEGIN PRIVATE KEY----------END PRIVATE KEY----- Authorization: Bearer abcdefghijklmnop\n' | envctl redact --no-env >pb2.test
nk 'authorization after inline pem scrubbed' "grep -q 'abcdefghijklmnop' pb2.test"
ck 'inline pem keeps its token' "grep -q '<redacted:private-key>' pb2.test"
printf 'DB_PASSWORD=hunter2-----BEGIN PRIVATE KEY-----\n' | envctl redact --no-env >pb3.test
nk 'prefix before BEGIN scrubbed' "grep -q 'hunter2' pb3.test"
printf 'x\n-----BEGIN PRIVATE KEY-----\n' >pb4.test
for ((i = 1; i <= 600; i++)); do echo "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw${i}" >>pb4.test; done
printf 'FIRSTSAFE=1\nSECONDSAFE=2\n' >>pb4.test
envctl redact --no-env <pb4.test >pb4.out
ck 'first line after carry cap is reprocessed' "grep -q '^FIRSTSAFE=1\$' pb4.out"
ck 'second line after carry cap kept' "grep -q '^SECONDSAFE=2\$' pb4.out"

group 'putty files in filter mode'
printf 'PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: demo\nPublic-Lines: 1\nAAAAB3NzaC1yc2EAAAADAQABAAABAQ\nPrivate-Lines: 2\nQWxsdGhlUHJpdmF0ZUtleUJ5dGVzSGVyZQ==\nTW9yZVByaXZhdGVLZXlCeXRlcw==\nPrivate-MAC: deadbeefdeadbeef\nafter=1\n' >ppk.test
envctl redact --no-env <ppk.test >ppk.out
nk 'putty private body scrubbed' "grep -q 'UHJpdmF0ZUtleUJ5dGVz' ppk.out"
nk 'putty mac value scrubbed' "grep -q 'deadbeefdeadbeef' ppk.out"
ck 'putty public line kept' "grep -q 'AAAAB3NzaC1yc2EA' ppk.out"
ck 'putty comment kept' "grep -q '^Comment: demo\$' ppk.out"
ck 'line after putty block kept' "grep -q '^after=1\$' ppk.out"
eq 'putty header and body collapse to one token each' '2' "grep -c '^<redacted:private-key>\$' ppk.out"

group 'standalone private jwks in filter mode'
printf '{"kty":"oct","k":"c3VwZXJzZWNyZXRrZXltYXRlcmlhbA"}\n' | envctl redact --no-env >jw1.test
nk 'bare private jwk scrubbed' "grep -q 'c3VwZXJzZWNyZXQ' jw1.test"
ck 'bare private jwk keeps token' "grep -q '<redacted:private-key>' jw1.test"
printf 'INFO jwk={"kty":"EC","crv":"P-256","x":"aa","d":"cHJpdmF0ZXNjYWxhcg"}\n' | envctl redact --no-env >jw2.test
nk 'log-prefixed private jwk scrubbed' "grep -q 'cHJpdmF0ZXNjYWxhcg' jw2.test"
ck 'log prefix survives jwk masking' "grep -q '^INFO jwk=' jw2.test"
ck 'public jwk untouched in filter' "printf '%s\n' '{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"aa\",\"y\":\"bb\"}' | envctl redact --no-env | grep -q '\"y\":\"bb\"'"

group 'prefixed assignments in filter mode'
ck 'export quoted multiword fully masked' "printf '%s\n' 'export DB_PASSWORD=\"correct horse battery staple\"' | envctl redact --no-env | grep -q '^export DB_PASSWORD=\"<redacted>\"\$'"
ck 'docker quoted multiword fully masked' "printf '%s\n' 'docker run -e DB_PASSWORD=\"correct horse battery staple\" image' | envctl redact --no-env | grep -q '^docker run -e DB_PASSWORD=\"<redacted>\" image\$'"
ck 'prefixed key colon value masked' "printf '%s\n' 'INFO DB_PASSWORD: CorrectHorse7' | envctl redact --no-env | grep -q '^INFO DB_PASSWORD: <redacted>\$'"
ck 'prefixed header key masked' "printf '%s\n' 'INFO X-API-Key: CorrectHorse7' | envctl redact --no-env | grep -q '^INFO X-API-Key: <redacted>\$'"
ck 'prefixed short basic credential masked' "printf '%s\n' 'INFO Authorization: Basic dXNlcjpwYXNz' | envctl redact --no-env | grep -q '^INFO Authorization: Basic <redacted>\$'"
ck 'bare scheme prose unharmed' "printf '%s\n' 'Basic knowledge is required here' | envctl redact --no-env | grep -q '^Basic knowledge is required here\$'"
ck 'innocent quoted value after key kept' "printf '%s\n' 'env APP_NAME=\"my cool app\" ./run' | envctl redact --no-env | grep -q '^env APP_NAME=\"my cool app\" ./run\$'"

group 'multiline quoted values in filter mode'
printf 'DB_PASSWORD="correcthorse\nsecretphrase"\nAFTER=ok\n' | envctl redact --no-env >mq1.test
nk 'continuation of quoted secret scrubbed' "grep -q 'secretphrase' mq1.test"
ck 'quoted secret masks to one line' "grep -q '^DB_PASSWORD=\"<redacted>\"\$' mq1.test"
ck 'line after quoted span kept' "grep -q '^AFTER=ok\$' mq1.test"
printf 'NOTES="just a note\nmore prose"\nTAIL=ok\n' | envctl redact --no-env >mq2.test
ck 'non-secret quoted span passes through' "grep -q 'more prose' mq2.test"

group 'env literal edge cases'
printf 'DB_PASSWORD=correcthorse\nAPI_TOKEN=abcdefghi\n' >lit2.test
printf 'DB_PASSWORD=hunter2-----BEGIN PUBLIC KEY-----\n' >pem1.test
ck 'lowercase password from env scrubbed' "echo 'login password correcthorse rejected' | envctl redact lit2.test | grep -q '^login password <redacted> rejected\$'"
ck 'lowercase token from env scrubbed' "echo 'token abcdefghi leaked' | envctl redact lit2.test | grep -q '^token <redacted> leaked\$'"
eq 'public pem substring no longer exempts strong keys' '<redacted>' "envctl --redact get pem1.test DB_PASSWORD"

group 'write failure reporting'
if [[ -w /dev/full ]]; then
	nk 'filter reports write failure' "printf 'API_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n' | envctl redact --no-env >/dev/full 2>/dev/null"
	printf 'A=1\n' >wf.test
	nk 'dry-run reports write failure' "envctl --dry-run set wf.test A 2 >/dev/full 2>/dev/null"
	nk 'get reports write failure' "envctl get wf.test A >/dev/full 2>/dev/null"
fi

printf '\n'
if ((${#failures[@]} == 0)); then
	printf '%d passed\n' "${passed}"
	exit 0
fi
printf '%d passed, %d FAILED:\n' "${passed}" "${#failures[@]}"
printf '  %s\n' "${failures[@]}"
exit 1
