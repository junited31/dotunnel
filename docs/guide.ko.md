# 설치 및 운영 안내

<p align="center"><img src="../assets/dotunnel.png" alt="dotunnel: 속이 뚫린 원기둥으로 형상화한 터널" width="640"></p>

[English front page](../README.md) · [한국어](../README.ko.md) · [English guide](guide.md) · [설계](../DESIGN.md) · [config 예시](../config.example.json) · [로고 asset](../assets/dotunnel.png) · [라이선스](../LICENSE)

이 안내는 설치, private Tunnel 설정, workspace 도구와 선택 native CLI 작업을 설명합니다. `dotunnel`은 로컬 stdio MCP 서버이며 호스팅 서비스, 공개 HTTP endpoint 또는 임의 코드의 sandbox가 아닙니다.

## 1. 설치

root가 아닌 Linux 계정, Python 3.11 이상, `venv`와 `pip`가 포함된 `python3`, `curl`, `sha256sum`, wheel과 의존성을 받을 네트워크 연결이 필요합니다. `uv`는 필요하지 않습니다. 의존성은 격리된 가상환경에 binary wheel로 설치합니다.

### 공개 설치 스크립트

front page의 한 줄 명령은 GitHub 로그인 없이 공개 저장소 `main`의 `install.sh`를 내려받아 현재 사용자 권한으로 실행합니다. `curl | sh`는 해당 스크립트를 실행하므로 스크립트 자체를 읽고 신뢰해야 합니다. 설치 도구는 고정 wheel을 검증하지만 wheel checksum이 shell 스크립트까지 인증하는 것은 아닙니다. 설치 스크립트는 패키지만 설치하며 piped stdin에서 대화형 setup을 실행하지 않습니다.

공개 설치는 `$HOME/.local/share/dotunnel/venv`를 사용하고 `$HOME/.local/bin/dotunnel`을 제공합니다. 기존 설치 경로나 무관한 launcher를 덮어쓰지 않습니다. sudo 사용, 계정·권한 변경, shell startup 수정, 서비스 실행, 공식 Tunnel client 설치, key 생성이나 Tunnel 설정 변경을 하지 않습니다. launcher를 찾지 못하면 `$HOME/.local/bin`을 직접 `PATH`에 추가하거나 절대 경로로 실행하세요. shell startup 파일은 자동 수정하지 않습니다.

### 수동 설치

내려받은 shell 스크립트를 실행하고 싶지 않다면 v0.1.4 release wheel을 직접 다운로드하세요. GitHub 로그인과 `gh`는 필요하지 않습니다. 설치 **전에** 기대하는 byte 수와 SHA-256을 모두 확인하세요.

```sh
set -eu
umask 077
install="$HOME/.local/share/dotunnel/venv"
if [ -e "$install" ] || [ -L "$install" ]; then
  printf '%s\n' "Install path already exists; use dotunnel update instead." >&2
  exit 1
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
wheel="$tmp/dotunnel-0.1.4-py3-none-any.whl"
curl --fail --location --output "$wheel" \
  https://github.com/junited31/dotunnel/releases/download/v0.1.4/dotunnel-0.1.4-py3-none-any.whl
test "$(wc -c < "$wheel")" -eq 80847
printf '%s  %s\n' \
  6ed19be1672ac3961f0e8230abd43af47c08eee4720ad2898b21d3ee6fc1af0f \
  "$wheel" | sha256sum --check -
python3 -I -m venv "$install"
"$install/bin/python" -I -m pip --isolated install --only-binary :all: "$wheel"
"$install/bin/dotunnel" help
```

byte 수나 checksum이 다르면 중단하세요. 이 수동 설치는 `$HOME/.local/share/dotunnel/venv/bin/dotunnel`을 직접 실행하며 한 줄 설치 스크립트의 `$HOME/.local/bin/dotunnel` launcher는 만들지 않습니다. 기존 설치 경로를 교체하지 마세요. 기존 설치에서는 `dotunnel update`를 사용하세요.

이 수동 설치의 setup 명령은 venv의 절대 경로를 사용합니다.

```sh
"$HOME/.local/share/dotunnel/venv/bin/dotunnel" setup --directory "$HOME/.dotunnel-setup"
```

## 2. 실행 계정과 private 경로 분리

프로세스는 Linux 실행 계정의 파일 및 작업 권한을 그대로 가집니다. sudo나 광범위한 그룹이 없는 전용 비-root 계정을 권장합니다. 기존 계정을 쓰기 전에 그룹을 확인하세요. `dotunnel`은 계정을 만들거나 그룹·sudoers를 바꾸거나 다른 디렉터리를 재귀적으로 소유 변경하지 않습니다. 계정 분리는 노출을 줄일 뿐 완전한 sandbox가 아닙니다.

설치 프로그램, trusted config/credential, writable workspace는 서로 분리하세요. config와 key를 workspace나 source control에 넣지 마세요. setup은 private workspace를 만들고 작업이 없는 상태(`tasks: []`)로 시작합니다. MCP 서버에는 별도 사용자 인증이 없으므로 로컬 stdio 프로세스와 Tunnel에 접근할 주체를 제한하세요.

## 3. Private Secure MCP Tunnel 설정

setup 전에 OS/architecture에 맞는 공식 [tunnel-client](https://github.com/openai/tunnel-client/releases/latest)를 별도로 설치하고 공식 checksum을 검증하세요. ChatGPT 개발자용 MCP 사용 자격, 대상 계정/workspace, [Platform Tunnel 설정](https://platform.openai.com/settings/organization/tunnels) 권한, Tunnel ID가 필요합니다. Tunnel 생성·편집에는 Tunnels **Read+Manage**, 앱 사용에는 **Read+Use** 권한이 필요합니다. [Platform API keys](https://platform.openai.com/settings/organization/api-keys)에서 Tunnels Read+Use만 허용하는 **Restricted** runtime API key를 만들고 Admin key는 사용하지 마세요. `dotunnel`은 권한 부여, Platform 로그인, Tunnel 생성, key 발급 또는 공식 client 다운로드를 하지 않습니다.

실제 대화형 터미널에서 setup을 실행합니다.

```sh
"$HOME/.local/share/dotunnel/venv/bin/dotunnel" setup --directory "$HOME/.dotunnel-setup"
```

새 Tunnel이나 key는 새 디렉터리에 설정하세요. setup은 Tunnel ID를 묻고 기존 runtime key를 숨김 터미널 입력으로 받습니다. key를 argv, profile, workspace에 넣지 않습니다. private config/profile/key 파일과 분리된 workspace를 만들며 디렉터리는 mode 0700, 파일은 mode 0600입니다. 사용자 지정 경로도 버전 관리에서 제외하세요. setup 디렉터리와 client/CLI 실행 파일·인증 참조 경로의 상위 디렉터리는 신뢰할 수 있는 소유권이어야 하며 신뢰할 수 없는 사용자가 쓸 수 없어야 합니다. symlink와 안전하지 않은 상위 경로는 거부됩니다.

setup은 공식 client의 설정 doctor를 확인한 뒤 명시적으로 동의할 때만 선택적 foreground 연결을 시작합니다. 설정 doctor 성공은 원격 인증 성공이 아닙니다. 실행을 선택하면 최대 45초 동안 live/ready health와 성공한 control-plane poll을 기다립니다. 인증 readiness가 없으면 setup이 시작한 client만 중지합니다. 이후 같은 Tunnel ID로 [ChatGPT 앱 등록](https://chatgpt.com/plugins)을 안내할 수 있습니다. ChatGPT에는 runtime key를 입력하지 말고 Tunnel 연결을 선택해 Tunnel ID를 지정하세요. 대화형 입력을 유지하세요. 취소나 오류 뒤에도 private 파일이 남을 수 있으므로 재시도에는 새 디렉터리를 쓰세요. 서비스나 자동 시작은 만들지 않습니다.

기존 디렉터리에서 setup을 다시 실행하면 선택 CLI 연동만 설정하며 key/profile은 읽거나 덮어쓰지 않습니다. 새 Tunnel/key에는 새 디렉터리를 사용하세요. Tunnel ID 하나에는 stdio client 하나만 활성화할 수 있습니다.

### 기존 profile migration

v0.1.0–v0.1.2에서 만든 profile은 패키지 업데이트가 수정하지 않습니다. v0.1.3 이상으로 시작하기 전에 trusted `profile.yaml`의 `mcp.commands[].command`에서 절대 Python 경로와 `-m dotunnel` 사이에 `-I`를 넣으세요. interpreter, config 경로, Tunnel ID, key 참조는 유지합니다. 새 setup은 이미 격리 명령을 만듭니다.

## 4. 진단, 업데이트와 연결 해제

- **`dotunnel doctor`**는 읽기 전용입니다. client나 모델을 실행하거나 설정을 변경하지 않습니다. setup/config, 선택 client, 선택 Bubblewrap 상태를 검사합니다. 유효한 config나 인증 파일 metadata만으로 provider 인증 성공을 입증할 수 없습니다. live/ready와 성공한 control-plane poll을 관찰하지 못하면 exit 2입니다. `--directory DIR`, 필요하면 `--tunnel-client /절대/경로`로 경로를 지정하세요.
- **`dotunnel update`**는 GitHub CLI나 로그인 없이 HTTPS로 최신 안정 public GitHub release를 확인하고 설치 전에 묻습니다. non-root Linux의 non-editable venv 설치만 지원하며 더 높은 설치 버전으로 downgrade하지 않습니다. 설치 전에 release wheel 이름·크기·GitHub SHA-256과 package name/version을 확인한 뒤 binary-only 설치를 합니다. network/TLS 오류, GitHub rate limit, release 부재, EOF 또는 비대화형 입력은 설치하지 않고 exit 2이며 Ctrl-C는 exit 130입니다. 부분 설치 rollback은 보장되지 않습니다. config, credential, Tunnel 설정을 바꾸거나 실행 중인 프로세스를 재시작하지 않습니다. 작업이 끝난 뒤 MCP/client를 직접 재시작하세요. 0.1.4 이전 설치본에는 구 updater가 남아 있으므로 기존 updater를 한 번 사용하거나 검증된 최신 wheel을 수동 설치해 새 updater를 받으세요.
- **연결 해제:** foreground client에 Ctrl-C를 보내면 해당 client는 멈추지만 접근 권한까지 취소하지는 않습니다. 완전한 해제에는 ChatGPT 앱 연결 해제/삭제, Tunnel association 제거, runtime key 폐기가 필요할 수 있습니다. ChatGPT에 이미 전송된 데이터는 회수되지 않습니다. 프로젝트는 지속 서비스 생성을 하지 않습니다. 직접 구성한 서비스가 있다면 서버 정책에 따라 관리하세요.

## 5. Workspace, 작업과 MCP 도구

setup이 초기 workspace와 config를 만듭니다. 직접 구성할 때는 [`config.example.json`](../config.example.json)에서 시작하고 config를 workspace 밖에 둔 뒤 `root`를 존재하는 절대 workspace 경로로 지정하세요. config는 실행 계정 소유의 private regular file이어야 합니다. symlink, hardlink, group/world 쓰기는 거부됩니다. root에는 `/`, 실행 계정 home, 프로그램/config 경로를 사용할 수 없습니다. 상위 symlink, 중복/알 수 없는 필드도 거부됩니다.

초기 `tasks: []`는 명령 실행 권한을 주지 않습니다. 관리자가 등록하는 작업은 이름, 설명, workspace 밖 절대 `argv[0]`, 고정 인자, workspace 기준 상대 `cwd`, timeout을 사용합니다(기본 60초, 최대 300초). 최대 50개까지 등록할 수 있습니다. 호출자는 작업 이름만 선택하며 인자, 환경, shell, 디렉터리, timeout을 바꿀 수 없습니다. 등록 전에 실행 파일·코드·side effect를 검토하세요. 고정 작업은 MCP 계정의 전체 OS 권한으로 실행되며 workspace는 OS sandbox가 아닙니다.

| 도구 | 동작 및 제한 |
|---|---|
| `list_files(path=".")` | 즉시 하위 항목만 반환; 최대 200개 결과, 1,000개 entry 방문 |
| `read_file(path)` | UTF-8 파일 내용과 SHA-256; 최대 64 KiB |
| `search_files(query, path=".")` | literal 검색; 최대 100개 match, 1,000개 entry, 4 MiB scan |
| `write_file(path, content, expected_sha256=null)` | `null`은 새 파일만 생성; 기존 파일 교체에는 현재 hash 필요 |
| `list_tasks()` | 등록 작업의 이름과 설명 |
| `run_task(name)` | 고정 작업을 시작하고 result ID를 바로 반환 |
| `get_task_result(result_id)` | 현재 프로세스의 실행/최종 결과 조회; ID 최대 20개 보관 |

경로는 `root` 기준 상대 경로입니다. 절대 경로, `..`, symlink/hardlink, 특수 파일, 숨김 경로와 일반적인 credential/key 이름은 거부 또는 제외됩니다. 부모 디렉터리가 이미 있어야 하고 delete/move/mkdir/chmod 도구는 없습니다. 쓰기 전 hash 검사는 외부 편집과의 atomic transaction이 아니며 OS/I/O 오류 시 일부만 기록될 수 있습니다. 한 번에 한 작업만 실행하며 출력은 16 KiB까지 보관하고 나머지는 누적하지 않습니다. 작업 stdin은 닫혀 있고 최소 환경만 전달되지만 CPU, memory, disk, network 격리는 아닙니다. 새 session으로 빠져나간 자식은 process-group 정리로 종료되지 않을 수 있습니다.

`run_task(name)`을 한 번 호출해 `result_id`를 보관한 뒤 제한된 간격으로 `get_task_result(result_id)`를 조회하세요. 조회는 작업을 다시 시작하지 않습니다. `exit_code`, `output`, `truncated`를 확인하세요. `completed`가 exit code 0을 뜻하지 않습니다. 실행 중 partial output은 없습니다. ID는 메모리에 최대 20개만 보관되고 서버 재시작 시 무효화됩니다. 시작 응답을 잃어도 작업을 무작정 재시도하지 마세요.

## 6. 선택 native CLI 작업

운영자가 명시적으로 등록하지 않으면 CLI 작업은 비활성화되어 있습니다. MCP 도구를 추가하지 않으며 등록만으로 모델을 실행하거나 provider 로그인을 검증하지 않습니다. Codex, Claude Code 또는 OMP native CLI와 provider 접근은 별도 설치·설정이 필요합니다. `dotunnel setup`은 PATH의 안전한 launcher를 실행하지 않고 탐지합니다. 선택 작업에는 non-root Linux와 사용 가능한 `/usr/bin/bwrap`(Bubblewrap)이 필요합니다. 기본 Tunnel, 파일 도구와 고정 작업에는 필요하지 않습니다. Bubblewrap은 mount/PID namespace를 만들고 capability를 제거하며 allowlist candidate만 `/workspace`에 제공하고 `/home/job`을 별도 HOME으로 씁니다. setup은 실행 파일 존재뿐 아니라 namespace 생성도 확인합니다. Bubblewrap이 없고 sudo 사용이 가능해 보이면 setup이 설치를 제안할 수 있습니다. 설치됐지만 사용할 수 없으면 kernel/AppArmor 정책이 비특권 namespace를 허용해야 하며 재설치로 해결되지 않습니다. 공유 서버에서는 실행 계정에 sudo를 주는 대신 관리자가 시스템 패키지를 설치하세요. 연동을 건너뛰고 나중에 설정할 수 있습니다.

운영자 config는 각 backend의 runtime, 인증 참조, MCP workspace와 분리된 source root, target 별칭, 허용 파일과 editable subset을 writable workspace 밖에서 고정합니다. `review`는 읽기 전용이며 `edit`는 allowlist에 있는 기존 파일만 변경할 수 있습니다. 작업은 허용 파일을 격리 candidate에 복사하며 원본에 자동 반영하거나 테스트·commit/push·임의 shell을 실행하지 않습니다. 작업 registry는 전체 선택을 검증한 뒤 교체하며 해제 시 setup이 관리하는 해당 task만 제거합니다. 인증 참조는 읽기 전용이지만 native CLI는 같은 사용자로 실행되어 이를 읽을 수 있습니다. provider 네트워크도 공유하므로 CLI에서 credential을 숨기거나 외부 통신을 차단하지 않습니다. setup은 provider 인증 성공을 증명하지 않습니다. 비밀 파일을 허용하지 마세요. 선택 source·instruction·결과는 provider를 통해 ChatGPT로 전달될 수 있습니다.

설정한 request 파일에 `{ "target": "alias", "mode": "review", "instruction": "..." }`만 기록하고 등록 작업의 `run_task`를 한 번 호출한 뒤 결과를 조회합니다. `target`은 등록된 별칭, `mode`는 `review`/`edit`, `instruction`은 UTF-8 최대 8 KiB입니다. 실행 중 request 파일을 덮어쓰지 마세요. target당 최대 32개 regular file, 파일당 64 KiB입니다. MCP task timeout은 정리 시간을 포함해 native 200초 제한보다 길게 설정하세요(예: 240초). native 출력 캡처는 최대 1 MiB입니다. 결과가 가리키는 report와 최대 48 KiB의 SHA-256 주소형 diff 조각을 읽고 검증하세요. `candidate_ready`는 candidate가 준비됐다는 뜻일 뿐 적용이나 정확성을 뜻하지 않습니다. report의 `verification`은 `not_run`입니다.

- **Codex**에는 experimental `dynamicTools`/Code Mode와 effective-feature 조회를 지원하는 호환 native app-server 설치본, `codex-code-mode-host` companion이 필요합니다. 호환되지 않으면 거부하며 `exec`나 shell로 우회하지 않습니다.
- **Claude Code**에는 일반 `/login` credential이 아닌 `claude setup-token`의 장기 토큰이 필요합니다. `dotunnel claude-token --output PATH`로 대화형 private 토큰 파일을 새로 만들며 `--replace`를 지정하지 않으면 기존 파일을 덮어쓰지 않습니다. 토큰은 argv나 mount가 아니라 격리 프로세스의 `CLAUDE_CODE_OAUTH_TOKEN`으로 전달됩니다. 같은 UID의 Claude가 읽을 수 있으므로 토큰이 유출되면 폐기하고 교체하세요. Claude는 `--safe-mode --restricted`와 고정 파일 도구로 실행되며 host 설정, hooks, plugins, skills, MCP server, session을 mount하지 않습니다.
- **OMP** 출력은 frame별로 검증하며 누적 진행/도구 본문은 저장하지 않습니다. 형식이 틀리거나 너무 큰 frame, 완료되지 않은 최신 turn은 이전 완료 결과를 재사용하지 않고 실패합니다.

native 실행 실패는 `status: failed`, `error_code: NATIVE_FAILED`와 허용된 `native_error_code`(`SANDBOX_UNAVAILABLE`, `NATIVE_UNAVAILABLE`, `TIMEOUT`, `OUTPUT_LIMIT`, `NATIVE_FAILURE`, `INVALID_NATIVE_STREAM`), 고정 `native_detail`(`AUTH_FAILED`, `RATE_LIMITED`, `PROVIDER_ERROR`, `PERMISSION_DENIED`, `UNSUCCESSFUL_RESULT`, `INVALID_RESULT`, `EMPTY_RESULT`, `SUMMARY_TOO_LARGE`, `NO_RESULT`, `INVALID_STREAM`, `EXIT_NONZERO`)만 반환하며 raw CLI log는 반환하지 않습니다. 그 밖의 실패는 `CANDIDATE_INVALID`, `SOURCE_CONFLICT`, `ARTIFACT_FAILURE`, `JOB_FAILED`, 입력 거부는 `INVALID_REQUEST`, `INVALID_CONFIG`로 구분합니다(거부 exit 2, 작업 실패 exit 1). 안전 거부를 성공으로 처리하거나 자동 재시도하지 마세요.

## 7. Secret을 공개하지 않는 개발

source checkout을 private runtime 설정·key·쓰기 가능한 workspace와 분리하세요. `.gitignore`는 실수로 stage하는 것을 줄일 뿐 이미 tracked인 파일이나 `git add -f`를 막지 않습니다. private 저장소에도 유출 방지가 필요합니다.

[Gitleaks](https://github.com/gitleaks/gitleaks/releases)를 설치하고(8.30.1로 검증), release checksum을 확인한 뒤 `gitleaks`를 `PATH`에 두세요. 각 개발 checkout에서:

```sh
git config --get core.hooksPath
# 기존 hook 경로나 .git/hooks/pre-commit이 사용 중이면 덮어쓰지 말고
# 기존 hook에 이 검사를 통합하세요.
git config --local core.hooksPath .githooks
gitleaks git --log-opts=--all --redact=100 --no-banner
```

실행 가능한 `.githooks/pre-commit`은 staged 변경만 검사합니다. secret 탐지, 검사기 부재, 검사 timeout, 검사기 오류 시 커밋을 거부하고 탐지 값은 log에서 가립니다. unstaged 변경은 커밋에 포함되지 않으며 이 hook의 검사 대상도 아닙니다.

public push/PR CI도 fetched Git 이력을 검사하고 Python 3.11·3.13에서 Linux 회귀 테스트, wheel 빌드, checkout 밖에서 설치된 CLI 검사를 실행합니다. 읽기 전용 권한의 격리된 GitHub-hosted Ubuntu runner를 사용하며 운영자/worker credential을 제공하지 않습니다. CI 실패는 failed check로 보고됩니다. branch protection은 별도 저장소 정책입니다.

push 전 `git diff --cached`를 로컬에서 검토하고 runtime/key 파일이 없는지 확인하세요. 위 history 검사는 runtime 디렉터리가 아니라 source 저장소에서 실행합니다. 민감한 diff·검사 보고서를 공개 issue에 붙이지 마세요. 지원되는 저장소에서는 GitHub secret scanning·push protection도 켜세요. 모든 secret을 탐지할 수는 없고 hook은 우회 가능하며 provider push protection에도 패턴·우회 한계가 있습니다. 실제 secret이 commit/push되면 먼저 폐기·교체하세요. 최신 파일을 삭제해도 Git 이력에는 남습니다.

미공개 기능은 별도 **private 저장소**를 만들고 public source를 clone한 뒤 private remote에 push해 개발하세요. public GitHub fork는 public이며 독립적으로 private으로 바꿀 수 없습니다([GitHub fork visibility](https://docs.github.com/en/pull-requests/reference/forks)). public upstream은 fetch용으로 두고 검토한 코드 변경만 공개하세요. private runtime 파일·운영 기록은 보내지 않습니다. 별도 private 개발 저장소는 선택 사항이며 실행 필수 요소가 아닙니다.

## 추가 참고

- [English front page](../README.md) · [한국어 front page](../README.ko.md)
- [설계 및 runtime 경계](../DESIGN.md)
- [최소 config 예시](../config.example.json)
- [로고 asset](../assets/dotunnel.png) · [MIT License](../LICENSE)
- [OpenAI Secure MCP Tunnel 공식 문서](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
