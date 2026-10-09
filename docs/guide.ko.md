# 설치 및 운영 안내

<p align="center"><img src="../assets/dotunnel.png" alt="dotunnel: 속이 뚫린 원기둥으로 형상화한 터널" width="640"></p>

[English front page](../README.md) · [한국어](../README.ko.md) · [English guide](guide.md) · [설계](../DESIGN.md) · [config 예시](../config.example.json) · [로고 asset](../assets/dotunnel.png) · [라이선스](../LICENSE)

이 안내는 설치, private Tunnel 설정, workspace 도구, 선택 native CLI 작업과 선택 Herdr/tmux agent supervision을 설명합니다. `dotunnel`은 로컬 stdio MCP 서버이며 호스팅 서비스, 공개 HTTP endpoint 또는 임의 코드의 sandbox가 아닙니다.

## 1. 설치

root가 아닌 Linux 계정, Python 3.11 이상, `venv`와 `pip`가 포함된 `python3`, `curl`, `sha256sum`, wheel과 의존성을 받을 네트워크 연결이 필요합니다. `uv`는 필요하지 않습니다. 의존성은 격리된 가상환경에 binary wheel로 설치합니다.

### 공개 설치 스크립트

front page의 한 줄 명령은 GitHub 로그인 없이 공개 저장소 `main`의 `install.sh`를 내려받아 현재 사용자 권한으로 실행합니다. `curl | sh`는 해당 스크립트를 실행하므로 스크립트 자체를 읽고 신뢰해야 합니다. 설치 도구는 고정 wheel을 검증하지만 wheel checksum이 shell 스크립트까지 인증하는 것은 아닙니다. 설치 스크립트는 패키지만 설치하며 piped stdin에서 대화형 setup을 실행하지 않습니다.

공개 설치는 `$HOME/.local/share/dotunnel/venv`를 사용하고 `$HOME/.local/bin/dotunnel`을 제공합니다. 기존 설치 경로나 무관한 launcher를 덮어쓰지 않습니다. sudo 사용, 계정·권한 변경, shell startup 수정, 서비스 실행, 공식 Tunnel client 설치, key 생성이나 Tunnel 설정 변경을 하지 않습니다. launcher를 찾지 못하면 `$HOME/.local/bin`을 직접 `PATH`에 추가하거나 절대 경로로 실행하세요. shell startup 파일은 자동 수정하지 않습니다.

### 수동 설치

내려받은 shell 스크립트를 실행하고 싶지 않다면 v0.1.5 release wheel을 직접 다운로드하세요. GitHub 로그인과 `gh`는 필요하지 않습니다. 설치 **전에** 기대하는 byte 수와 SHA-256을 모두 확인하세요.

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
wheel="$tmp/dotunnel-0.1.5-py3-none-any.whl"
curl --fail --location --output "$wheel" \
  https://github.com/junited31/dotunnel/releases/download/v0.1.5/dotunnel-0.1.5-py3-none-any.whl
test "$(wc -c < "$wheel")" -eq 123908
printf '%s  %s\n' \
  5b617552d1d9dbaabd4209a99f42c4a25e7757fad8c3e9a0e684d9f01a949810 \
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

setup은 공식 client의 설정 doctor를 확인한 뒤 명시적으로 동의할 때만 선택적 foreground 연결을 시작합니다. 설정 doctor 성공은 원격 인증 성공이 아닙니다. 실행을 선택하면 최대 45초 동안 live/ready health와 성공한 control-plane poll을 기다립니다. 인증 readiness가 없으면 setup이 시작한 client만 중지합니다. 이후 같은 Tunnel ID로 [ChatGPT 앱 등록](https://chatgpt.com/plugins)을 안내할 수 있습니다. ChatGPT에는 runtime key를 입력하지 말고 Tunnel 연결을 선택해 Tunnel ID를 지정하세요. 대화형 입력을 유지하세요. 최종 권한 검토에서 취소하면 파일을 만들지 않으며, 승인 뒤 오류가 나면 private 파일이 남을 수 있습니다. 재시도 전 마지막 상태 메시지와 표시된 경로를 확인하세요. 서비스나 자동 시작은 만들지 않습니다.

기존 디렉터리에서 `dotunnel setup`을 다시 실행하면 workspace, MCP 파일 접근 규칙과 선택 CLI/live-supervision 설정을 함께 검토합니다. 기존 key와 profile 참조를 재사용하며 key 값은 읽거나 출력하지 않습니다. 기존 설정을 바꾸려면 일치하는 로컬 Tunnel client가 중지된 것을 확인해야 하고, 같은 Tunnel을 사용하는 다른 로컬·원격 client가 없다는 운영자 확인도 별도로 필요합니다. setup은 기존 다른 client나 서비스를 중지·재시작하지 않습니다. 저장한 권한은 새 MCP 서버 프로세스부터 적용됩니다.

### 통합 권한 검토 (0.1.6)

setup은 workspace, MCP 파일 규칙, 선택한 고정 CLI 작업과 선택 live-supervision 권한을 draft로 구성한 뒤 새 private artifact를 만들기 전에 표시합니다. 최종 요약에는 경로, read/write 규칙, 고정 작업의 source/editable 범위, live project/profile action, 실행 파일 metadata, 유지되는 task 명령이 포함됩니다. 마지막 `[y/N]` 승인은 기본값이 No입니다. Enter를 누르면 key 입력이나 파일 변경 없이 취소됩니다. key 값은 요약에 출력하지 않습니다.

새 live supervision에 state directory가 필요하면 초기화 여부를 별도 기본 No로 확인합니다. 초기화는 state만 만들며 agent를 시작하거나 runtime scope를 승인하지 않습니다. 승인 후 private 참조와 작업 artifact를 준비하고 전체 registry를 검증한 다음 setup config를 마지막에 atomic publish합니다. 저장된 권한은 실행 중인 서버가 아니라 새 MCP 서버 프로세스에서 사용됩니다.

저장 후 setup은 로컬 Tunnel-client doctor를 실행합니다. Tunnel 연결 시작은 별도 기본 No foreground 선택이며, 해당 Tunnel을 쓰는 다른 로컬·원격 client가 없다는 명시 확인도 다시 필요합니다. setup은 native model/CLI를 실행하거나 서비스를 생성·재시작하지 않습니다.

저장 후 다른 client가 없다는 확인이나 foreground 시작을 거절하면 client는 중지 상태로 두고 shell-quoted 수동 명령과 ChatGPT 등록 안내를 표시합니다. 수동 시작 전에도 같은 Tunnel을 사용하는 다른 client가 없음을 별도로 확인하세요. 기존 setup에서 알 수 없는 Tunnel ID를 `None`으로 출력하지 않습니다.

오류가 나면 전체 rollback을 가정하지 말고 마지막 상태 메시지를 확인하세요. config publish 전에는 기존 설정이 권한 기준으로 남지만 setup이 시도했거나 남아 있을 수 있는 private 파일 경로를 표시할 수 있습니다. 해당 경로를 확인하고 안내된 방법으로 재시도하세요. config가 저장됐다고 표시된 뒤 doctor나 startup/readiness가 실패해도 설정은 되돌려지지 않습니다. foreground startup/readiness가 불확실하면 client가 시작됐을 수 있으므로 재시도 전에 상태를 확인하세요.

rename 이후 또는 rename 결과 자체가 불명확해 config 게시를 확인하지 못하면 준비한 참조 파일을 보존하고 새 연결을 시작하지 않았음을 알립니다. config가 이미 존재할 수 있으므로 재시도하거나 artifact를 삭제하기 전에 trusted identity와 참조 경로를 대조하세요. durability나 readback 검증 실패만으로 게시되지 않았다고 판단할 수 없습니다.

### 기존 profile migration

v0.1.0–v0.1.2에서 만든 profile은 패키지 업데이트가 수정하지 않습니다. v0.1.3 이상으로 시작하기 전에 trusted `profile.yaml`의 `mcp.commands[].command`에서 절대 Python 경로와 `-m dotunnel` 사이에 `-I`를 넣으세요. interpreter, config 경로, Tunnel ID, key 참조는 유지합니다. 새 setup은 이미 격리 명령을 만듭니다.

### 기존 설정 및 권한 migration

**0.1.6 업그레이드 경계:** `file_access`가 없는 구 설정은 `dotunnel serve`가 거부합니다. 패키지 설치만으로 해당 설정이 사용 가능해지지 않습니다. private backup을 보관하고 소유한 client를 중지한 뒤 기존 setup의 권한을 검토·migration하고, 저장된 config 검증 후 재시작하세요. setup directory 밖에서 수동 관리하는 config는 재시작 전에 문서화된 schema에 따라 검토한 파일 규칙과 supervision project/profile action을 명시하세요. 관련 없는 directory에 wizard를 실행하거나 기존 state/key 참조를 새로 만들지 마세요.

패키지 설치만으로 기존 setup을 migration하지 않습니다. 기존 설정에 대화형 `dotunnel setup --directory PATH`를 실행해 전체 draft를 검토하세요. 해당 로컬 Tunnel client가 실행 중이거나 소유권/상태를 확인할 수 없으면 setup은 수정을 거부합니다. 직접 소유한 client를 중지한 뒤 다시 실행하세요. 같은 Tunnel을 사용하는 다른 로컬·원격 client가 없다는 별도 기본 No 확인도 필요하며, 로컬 process 검사만으로 이를 증명할 수는 없습니다. 없거나 안전하지 않은 기존 supervision state를 자동 생성·회전하지 않습니다.

setup 소유 native CLI task는 CLI가 없어졌거나 job 문서가 잘못됐어도 명시적으로 등록 해제할 수 있습니다. 제거는 기본 No이며 최종 draft 승인도 필요합니다. task 등록만 제거하고 기존 job/request 파일은 삭제하지 않습니다. 선택 Bubblewrap/integration 설정의 skip은 기존 작업의 선택 해제가 아닙니다. 기존 등록을 기본 유지하고 별도 제거 선택을 제공합니다. 유지할 job은 검토한 workspace 기준으로 검증합니다. 기존 supervision state는 읽기 전용으로 열고 게시 직전 authority identity를 다시 확인합니다. 없거나 손상·변경된 state는 저장을 거부하며 자동 생성·회전하지 않습니다.

`file_access`가 없는 legacy 설정은 기존 전체 workspace 접근을 줄이지 않도록 `tree .` read 및 write 규칙으로 변환됩니다. 기존 read/write 규칙을 유지할지 묻는 항목은 기본값이 Yes입니다. 더 좁은 경로를 입력하려면 No를 선택하세요. 그렇지 않으면 최종 요약에 전체 tree 권한이 표시되며 요약을 승인해야 저장됩니다. 기존 supervision 권한은 project 상한과 profile별 action으로 명시적으로 변환되며 자동으로 비우지 않습니다. `executable_policy`가 없는 legacy live profile은 `compatible` 또는 `strict`를 선택하도록 묻고, Enter는 `compatible`입니다. 이전 writable/multiple-link 실행 파일 metadata 거부를 유지하려면 `strict`를 선택하세요.

## 4. 진단, 업데이트와 연결 해제

- **`dotunnel doctor`**는 읽기 전용입니다. client나 모델을 실행하거나 설정을 변경하지 않습니다. setup/config, 선택 client, 선택 Bubblewrap 상태를 검사합니다. 유효한 config나 인증 파일 metadata만으로 provider 인증 성공을 입증할 수 없습니다. live/ready와 성공한 control-plane poll을 관찰하지 못하면 exit 2입니다. `--directory DIR`, 필요하면 `--tunnel-client /절대/경로`로 경로를 지정하세요.
- **`dotunnel update`**는 GitHub CLI나 로그인 없이 HTTPS로 최신 안정 public GitHub release를 확인하고 설치 전에 묻습니다. non-root Linux의 non-editable venv 설치만 지원하며 더 높은 설치 버전으로 downgrade하지 않습니다. 설치 전에 release wheel 이름·크기·GitHub SHA-256과 package name/version을 확인한 뒤 binary-only 설치를 합니다. network/TLS 오류, GitHub rate limit, release 부재, EOF 또는 비대화형 입력은 설치하지 않고 exit 2이며 Ctrl-C는 exit 130입니다. 부분 설치 rollback은 보장되지 않습니다. config, credential, Tunnel 설정을 바꾸거나 실행 중인 프로세스를 재시작하지 않습니다. 작업이 끝난 뒤 MCP/client를 직접 재시작하세요. 0.1.4 이전 설치본에는 구 updater가 남아 있으므로 기존 updater를 한 번 사용하거나 검증된 최신 wheel을 수동 설치해 새 updater를 받으세요.
- **연결 해제:** foreground client에 Ctrl-C를 보내면 해당 client는 멈추지만 접근 권한까지 취소하지는 않습니다. 완전한 해제에는 ChatGPT 앱 연결 해제/삭제, Tunnel association 제거, runtime key 폐기가 필요할 수 있습니다. ChatGPT에 이미 전송된 데이터는 회수되지 않습니다. 프로젝트는 지속 서비스 생성을 하지 않습니다. 직접 구성한 서비스가 있다면 서버 정책에 따라 관리하세요.

## 5. Workspace, 작업과 MCP 도구

setup이 초기 workspace와 config를 만듭니다. 직접 구성할 때는 [`config.example.json`](../config.example.json)에서 시작하고 config를 workspace 밖에 둔 뒤 `root`를 존재하는 절대 workspace 경로로 지정하세요. config는 실행 계정 소유의 private regular file이어야 합니다. symlink, hardlink, group/world 쓰기는 거부됩니다. root에는 `/`, 실행 계정 home, 프로그램/config 경로를 사용할 수 없습니다. 상위 symlink, 중복/알 수 없는 필드도 거부됩니다.

### MCP 파일 접근 규칙

0.1.6부터 `file_access`가 네 MCP 파일 도구의 범위를 명시합니다. 새 setup의 `read`와 `write`는 모두 비어 있으며 workspace를 선택해도 내부 파일 접근 권한이 생기지 않습니다. 규칙은 workspace 기준 상대 경로이며 `kind: "file"`은 정확한 파일 하나, `kind: "tree"`는 해당 디렉터리와 이후 생성되는 파일을 포함한 모든 하위 경로입니다. 예:

```json
{
  "root": "/srv/example/workspace",
  "file_access": {
    "read": [
      {"path": "src", "kind": "tree"},
      {"path": "README.md", "kind": "file"}
    ],
    "write": [
      {"path": "src/change.py", "kind": "file"}
    ]
  },
  "tasks": []
}
```

모든 write 규칙은 read 허용 범위 안에 있어야 합니다. `list_files`와 `search_files`도 read 정책을 따르므로 허용되지 않은 entry·이름·match를 반환하지 않습니다. 허용 경로에 도달하기 위한 ancestor는 탐색에만 쓰일 수 있습니다. 숨김/credential 경로, link와 특수 파일에 대한 기존 제한은 그대로 적용됩니다. 이 규칙은 관리자가 정의한 `tasks`, 고정 CLI 작업이나 live agent를 제한하지 않습니다. 각각 별도 실행 경계를 가집니다.

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

Supervision은 별도 선택 API입니다. 기존 file/task 도구 일곱 개는 유지되며 supervision을 설정할 때만 공통 `agent_*` 도구 여덟 개가 추가됩니다. 설정과 안전 계약은 7절을 참고하세요.

경로는 `root` 기준 상대 경로입니다. 절대 경로, `..`, symlink/hardlink, 특수 파일, 숨김 경로와 일반적인 credential/key 이름은 거부 또는 제외됩니다. 부모 디렉터리가 이미 있어야 하고 delete/move/mkdir/chmod 도구는 없습니다. 쓰기 전 hash 검사는 외부 편집과의 atomic transaction이 아니며 OS/I/O 오류 시 일부만 기록될 수 있습니다. 한 번에 한 작업만 실행하며 출력은 16 KiB까지 보관하고 나머지는 누적하지 않습니다. 작업 stdin은 닫혀 있고 최소 환경만 전달되지만 CPU, memory, disk, network 격리는 아닙니다. 새 session으로 빠져나간 자식은 process-group 정리로 종료되지 않을 수 있습니다.

`run_task(name)`을 한 번 호출해 `result_id`를 보관한 뒤 제한된 간격으로 `get_task_result(result_id)`를 조회하세요. 조회는 작업을 다시 시작하지 않습니다. `exit_code`, `output`, `truncated`를 확인하세요. `completed`가 exit code 0을 뜻하지 않습니다. 실행 중 partial output은 없습니다. ID는 메모리에 최대 20개만 보관되고 서버 재시작 시 무효화됩니다. 시작 응답을 잃어도 작업을 무작정 재시도하지 마세요.

## 6. 선택 native CLI 작업

운영자가 명시적으로 등록하지 않으면 CLI 작업은 비활성화되어 있습니다. MCP 도구를 추가하지 않으며 등록만으로 모델을 실행하거나 provider 로그인을 검증하지 않습니다. Codex, Claude Code 또는 OMP native CLI와 provider 접근은 별도 설치·설정이 필요합니다. `dotunnel setup`은 PATH의 안전한 launcher를 실행하지 않고 탐지합니다. 선택 작업에는 non-root Linux와 사용 가능한 `/usr/bin/bwrap`(Bubblewrap)이 필요합니다. 기본 Tunnel, 파일 도구와 고정 작업에는 필요하지 않습니다. Bubblewrap은 mount/PID namespace를 만들고 capability를 제거하며 allowlist candidate만 `/workspace`에 제공하고 `/home/job`을 별도 HOME으로 씁니다. setup은 실행 파일 존재뿐 아니라 namespace 생성도 확인합니다. Bubblewrap이 없고 sudo 사용이 가능해 보이면 setup이 설치를 제안할 수 있습니다. 설치됐지만 사용할 수 없으면 kernel/AppArmor 정책이 비특권 namespace를 허용해야 하며 재설치로 해결되지 않습니다. 공유 서버에서는 실행 계정에 sudo를 주는 대신 관리자가 시스템 패키지를 설치하세요. 연동을 건너뛰고 나중에 설정할 수 있습니다.

운영자 config는 각 backend의 runtime, 인증 참조, MCP workspace와 분리된 source root, target 별칭, 허용 파일과 editable subset을 writable workspace 밖에서 고정합니다. `review`는 읽기 전용이며 `edit`는 격리 candidate 안의 허용된 기존 파일만 바꿀 수 있습니다. 이 source/editable 선택은 MCP `file_access`와 별개이며 한쪽 권한이 다른 쪽 권한을 뜻하지 않습니다. 작업은 원본을 자동 수정하거나 테스트·commit/push·임의 shell을 실행하지 않습니다. task registry는 전체 선택을 검증한 뒤 교체하며 해제 시 setup이 관리하는 해당 task만 제거합니다. native CLI는 같은 사용자로 실행되어 참조 credential을 읽을 수 있고 provider 네트워크도 공유합니다. 비밀 파일을 허용하지 마세요. 선택 source·instruction·결과는 provider를 통해 전송될 수 있습니다. 고정 작업은 Bubblewrap candidate 경계를 사용하지만 7절의 live Herdr/tmux agent는 이를 사용하지 않고 native OS 파일·인증 권한을 가집니다.

설정한 request 파일에 `{ "target": "alias", "mode": "review", "instruction": "..." }`만 기록하고 등록 작업의 `run_task`를 한 번 호출한 뒤 결과를 조회합니다. `target`은 등록된 별칭, `mode`는 `review`/`edit`, `instruction`은 UTF-8 최대 8 KiB입니다. 실행 중 request 파일을 덮어쓰지 마세요. target당 최대 32개 regular file, 파일당 64 KiB입니다. MCP task timeout은 정리 시간을 포함해 native 200초 제한보다 길게 설정하세요(예: 240초). native 출력 캡처는 최대 1 MiB입니다. 결과가 가리키는 report와 최대 48 KiB의 SHA-256 주소형 diff 조각을 읽고 검증하세요. `candidate_ready`는 candidate가 준비됐다는 뜻일 뿐 적용이나 정확성을 뜻하지 않습니다. report의 `verification`은 `not_run`입니다.

고정 작업을 setup에 등록하면 request control file마다 별도의 정확한 MCP file read/write 규칙을 확인합니다. setup은 승인할 경로를 표시하며 request 파일을 위해 workspace 전체 권한을 추가하지 않습니다.

- **Codex**에는 experimental `dynamicTools`/Code Mode와 effective-feature 조회를 지원하는 호환 native app-server 설치본, `codex-code-mode-host` companion이 필요합니다. 호환되지 않으면 거부하며 `exec`나 shell로 우회하지 않습니다.
- **Claude Code**에는 일반 `/login` credential이 아닌 `claude setup-token`의 장기 토큰이 필요합니다. `dotunnel claude-token --output PATH`로 대화형 private 토큰 파일을 새로 만들며 `--replace`를 지정하지 않으면 기존 파일을 덮어쓰지 않습니다. 토큰은 argv나 mount가 아니라 격리 프로세스의 `CLAUDE_CODE_OAUTH_TOKEN`으로 전달됩니다. 같은 UID의 Claude가 읽을 수 있으므로 토큰이 유출되면 폐기하고 교체하세요. Claude는 `--safe-mode --restricted`와 고정 파일 도구로 실행되며 host 설정, hooks, plugins, skills, MCP server, session을 mount하지 않습니다.
- **OMP** 출력은 frame별로 검증하며 누적 진행/도구 본문은 저장하지 않습니다. 형식이 틀리거나 너무 큰 frame, 완료되지 않은 최신 turn은 이전 완료 결과를 재사용하지 않고 실패합니다.

native 실행 실패는 `status: failed`, `error_code: NATIVE_FAILED`와 허용된 `native_error_code`(`SANDBOX_UNAVAILABLE`, `NATIVE_UNAVAILABLE`, `TIMEOUT`, `OUTPUT_LIMIT`, `NATIVE_FAILURE`, `INVALID_NATIVE_STREAM`), 고정 `native_detail`(`AUTH_FAILED`, `RATE_LIMITED`, `PROVIDER_ERROR`, `PERMISSION_DENIED`, `UNSUCCESSFUL_RESULT`, `INVALID_RESULT`, `EMPTY_RESULT`, `SUMMARY_TOO_LARGE`, `NO_RESULT`, `INVALID_STREAM`, `EXIT_NONZERO`)만 반환하며 raw CLI log는 반환하지 않습니다. 그 밖의 실패는 `CANDIDATE_INVALID`, `SOURCE_CONFLICT`, `ARTIFACT_FAILURE`, `JOB_FAILED`, 입력 거부는 `INVALID_REQUEST`, `INVALID_CONFIG`로 구분합니다(거부 exit 2, 작업 실패 exit 1). 안전 거부를 성공으로 처리하거나 자동 재시도하지 마세요.

## 7. 선택 Herdr/tmux agent supervision

trusted `dotunnel` config에 고정 `supervision` registry를 넣고 상태를 명시적으로 초기화해야 기능이 활성화됩니다. 설정한 Herdr session, tmux socket 또는 두 backend를 함께 사용할 수 있으며 connection은 최대 네 개입니다. Project는 canonical path와 허용 connection/profile을 고정하고 profile은 CLI 종류, 절대 실행 파일, 고정 인자를 지정합니다. 호출자는 cwd, 실행 파일, 인자나 환경을 전달할 수 없습니다. Supervision은 `0.1.5`부터 제공되며, `0.1.6`부터 대화형 setup이 이를 명시적 action 권한과 함께 구성할 수 있습니다. 패키지 설치나 업데이트만으로 활성화되지는 않습니다.

기본 [`config.example.json`](../config.example.json)은 의도적으로 최소 설정만 담습니다. 아래는 익명 sample 경로를 사용한 완전하고 문법적으로 유효한 config 예시입니다. 실제 trusted absolute path로 바꾸세요. Herdr와 tmux를 각각 명시적으로 설정하면 같은 `connections` 목록에서 함께 사용할 수 있습니다.

Live profile의 `executable_policy` 기본값은 `compatible`이며 `strict`를 선택할 수 있습니다. Compatible은 group/world 쓰기 가능하거나 hard link가 여러 개인 leaf 실행 파일을 허용할 수 있어 다른 작성자나 link 공유자가 live agent의 native 파일·인증 권한으로 실행되는 코드를 바꿀 수 있습니다. 이는 수용한 변조 위험이며 보안 보장이 아닙니다. Strict는 leaf 실행 파일의 writable mode와 다중 link를 다시 거부합니다. 소유권, 상위 경로, symlink, regular/executable file, set-ID 검사 등 나머지 검사는 두 정책에서 모두 적용됩니다. 이 설정은 6절 고정 Bubblewrap 작업이 아닌 live supervision profile에만 적용되며 agent action을 허용하지 않습니다.

```json
{
  "root": "/srv/example/workspace",
  "file_access": {"read": [], "write": []},
  "tasks": [],
  "supervision": {
    "state_dir": "/srv/example/state/supervision",
    "default_connection": "tmux-example",
    "connections": [
      {
        "id": "tmux-example",
        "backend": "tmux",
        "executable": "/usr/bin/tmux",
        "socket": "/srv/example/state/tmux-example.sock"
      }
    ],
    "projects": [
      {
        "id": "example-project",
        "path": "/srv/example/project",
        "connections": ["tmux-example"],
        "profiles": ["omp"],
        "allowed_actions": [],
        "profile_actions": {"omp": []}
      }
    ],
    "profiles": [
      {
        "id": "omp",
        "kind": "omp",
        "executable": "/usr/local/bin/omp",
        "executable_policy": "compatible",
        "args": [],
        "backends": ["tmux"],
        "input_mode": "bracketed-paste"
      }
    ],
    "protected_paths": ["/srv/example/protected"]
  }
}
```

MCP 요청을 받기 전에 상태를 초기화합니다.

```sh
dotunnel supervision init --config /path/to/trusted/config.json
dotunnel serve --config /path/to/trusted/config.json
```

`init`은 private 상태만 만들며 agent를 시작하지 않습니다. 상태 디렉터리는
실행 UID 소유, mode `0700`이어야 하고 파일은 mode `0600`이어야 하며 writable
MCP `root` 밖에 있어야 합니다.
MCP 시작 시 상태를 자동 생성하거나 손상된 상태를 조용히 복구하지 않습니다.
`dotunnel supervision reinit --config /path/to/trusted/config.json`은 자동 복구가
아닌 명시적 authority 회전에 사용합니다. terminal 확인이 필요하며 이전
namespace를 `<state_dir>.previous`에 보존합니다. 다음 회전 전 archive를
정리해야 합니다. 과거 handle, 승인, operation ID는 새 namespace의 권한이 아닙니다.

namespace 생성과 회전은 상태 디렉터리의 부모에 보존되는
`.dotunnel-owner-<소문자 hex 64자리>` 파일을 사용합니다. 상태 basename의
filesystem 바이트를 SHA-256으로 해시한 이름이며, 내용이 비어 있고 runtime UID
소유·`0600`·단일 hard link인 파일만 허용합니다. 잠금은 두 번의 rename, rollback,
최종 검증이 끝날 때까지 유지됩니다. 경합 명령은 새 namespace를 만들지 않고
`busy`를 반환합니다. 명령이 잠금을 보유할 수 있는 동안 파일을 삭제하거나
교체하지 마세요. cutover나 owner 파일 정리 전에는 이전 binary의 명령도
중지해야 합니다. 이전 root-inode 잠금만으로는 회전 중 active 경로가 없는
구간을 보호하지 못합니다.
쓰기 불가능한 부모 아래에 미리 만든 빈 private 상태 디렉터리는 owner 파일이
없으면 기존 root inode의 소유 잠금으로 초기화할 수 있습니다. 이 경로는 없는
root를 새로 만들거나 기존의 안전하지 않은 owner 파일을 우회하지 않습니다.
상태 디렉터리를 새로 만들거나 회전하려면 부모 디렉터리에 쓰기 권한이 필요합니다.
SIGKILL 뒤에는 명시적 재초기화가 크기·소유자·권한 검증을 통과한 atomic staging
파일 `.write-<소문자 hex 32자리>` 하나를 이전 namespace와 함께 보존할 수 있습니다.
시작 시에는 여전히 불완전한 namespace를 거부하며 staging 바이트를 승인이나
receipt로 승격하지 않습니다. 잘못되거나 안전하지 않은 staging 파일은 거부합니다.

### 도구, scope와 선택

공통 API는 정확히 여덟 도구를 등록합니다.

| 도구 | 계약 |
|---|---|
| `agent_status(connection?, project?, cursor?)` | 읽기 전용 inventory와 recovery 진단; 페이지당 최대 100행·64 KiB, registry/scope 변경 시 cursor 무효화 |
| `agent_read(target, lines=80)` | 최신 화면 tail을 최대 1–200행·16 KiB로 읽고 60초 유효한 signed observation 발급 |
| `agent_approve(scope)` | `connection_id:project_id`의 현재 config generation 승인 |
| `agent_revoke(scope)` | 해당 scope 철회; agent를 종료하거나 전달한 입력을 취소하지 않음 |
| `agent_start(project, profile, name, operation_id, connection?, worktree_branch?)` | 등록 profile 시작; `name`은 표시 문자열이지 target identity가 아님; worktree branch는 Herdr만 지원 |
| `agent_prompt(target, observation, text, operation_id)` | 전송 전에 handle, 현재 identity, 승인과 최신 observation 재확인; literal text 최대 8 KiB |
| `agent_answer(target, observation, keys, operation_id)` | 명시 선택한 소문자 key 최대 8개 전달: `enter`, `esc`, `up`, `down`, `left`, `right`, `tab`, `y`, `n`, `1`–`9` |
| `agent_wait(target, observation, timeout_seconds=60)` | 제한된 상태 변화를 기다리고 새 observation 반환; 최대 110초 |

새 project 권한에서 `projects[].allowed_actions`는 `read`, `start`, `prompt`, `answer`로 구성되는 상한입니다. `projects[].profile_actions`는 profile마다 허용할 `start`, `prompt`, `answer`를 별도로 지정하며 각 profile 권한은 project 상한 안에 있어야 합니다. `prompt`/`answer`에는 project `read`도 필요합니다. 새 권한은 모두 비어 있는 상태로 시작합니다. setup 시 선택한 action만으로 runtime scope가 승인되지는 않습니다. 정확한 `connection_id:project_id`의 `agent_approve`는 별도 승인입니다. Runtime 승인도 project/profile config에 없는 action을 추가할 수 없으며, 어느 live 권한도 MCP file 접근 권한이 아닙니다.

`agent_approve`와 `agent_revoke` scope는 정확히 `connection_id:project_id`이며
현재 config generation에 묶입니다. 이는 운영 실수를 막는 승인이지 사람 인증이
아닙니다. stdio MCP에는 별도 caller identity가 없으므로 stdio 프로세스와 Tunnel
접근을 제한하세요. Scope 변경은 기존 승인과 handle을 무효화하지만 이미 발생한
효과를 되돌리지는 않습니다.

Target은 signed opaque handle이며 display name, pane ID 또는 caller 입력 이름을
대신 사용할 수 없습니다. Recovery identity와 미해결 start 기록은 진단용이며
실행 가능한 target이 아닙니다. 기본 connection은 새 start만 선택하고 scope
승인, 모호한 기존 target 선택, agent 재시작, broadcast 또는 자동 fallback을
하지 않습니다. 기존 target은 handle로 명시 선택하며 이름으로 입양하지 않습니다.

Herdr가 제공하는 native process identity는 약할 수 있으므로 supervisor 재시작이나
connection 실패 뒤 다시 탐색해야 할 수 있습니다. tmux는 더 강한 managed identity
evidence를 사용합니다. 쓰기는 dotunnel이 고정 profile로 시작해 boot/server/pane/
process identity를 기록하고 재확인한 agent만 허용합니다. 임의의 기존 pane은 입력
대상으로 입양하지 않습니다. 기존 pane은 정확한 `read_targets` identity를 등록해
읽기 전용으로 관찰할 수 있습니다. 이 증거와 반복 검사도 입력 전달의 원자성이나
sandbox를 보장하지 않습니다. backend 상태, 화면 변화와 입력 확인은 논리적 작업
성공을 입증하지 않으며 tmux agent 상태가 `unknown`인 것은 정상일 수 있습니다.

tmux connection의 `read_targets`에 현재 서버·pane의 정확한 identity를 등록합니다.
PID·시작 시각은 십진 문자열입니다. 예시 값을 해당 `/proc` 증거로 바꾸세요.
Process가 교체되면 등록이 무효화되며 어떤 승인도 입력 권한을 만들지 않습니다.

```json
"read_targets": [{
  "project": "example-project", "native_id": "%3",
  "identity": {
    "boot_id": "00000000-0000-4000-8000-000000000000",
    "server_pid": "12345", "server_start": "100000",
    "pane_pid": "12346", "pane_start": "100001"
  }
}]
```

화면 observation과 native output에는 secret이 포함될 수 있으며 ANSI 정리는
redaction이 아닙니다.

### Durable operation과 실행 제한

각 start, prompt, answer에는 고유 `operation_id`가 필요합니다. Persistent receipt는
ID와 canonical request를 결합합니다. 같은 ID와 같은 payload를 다시 요청하면 native
효과를 재실행하지 않고 기록된 결과만 반환하며, 다른 내용의 ID 재사용은 conflict가
됩니다. `unknown` 시작/전달은 이미 효과가 있었을 수 있습니다. receipt와 recovery
진단을 살펴보고 target을 확인하기 전에는 같은 ID나 새 ID로 무작정 재시도하지
마세요. Recovery 기록은 handle이 아닙니다. Receipt와 target 기록은 각각 최대
1,000개, 각 64 KiB이며 자동 정리되지 않습니다.

`agent_revoke`의 `busy` 거절은 철회 완료가 아닙니다. 진행 중 mutation이 끝난 뒤
명시적으로 다시 철회하고 상태를 확인하세요.

공유 native CLI pool은 동시에 최대 네 process를 실행합니다. 일반 status/조회/입력
호출은 20초, start 전체는 180초 deadline을 사용하며 `agent_wait`는 최대 110초입니다.
stdout/stderr 합산 캡처는 4 MiB로 제한됩니다. status와 화면도 앞서 설명한 크기로
제한되며 이 한도는 agent 완료나 작업 정확성을 보장하지 않습니다.
정상 leader 종료 시 일반 helper가 stdout/stderr를 상속했더라도, pool은 pipe EOF를
기다리기 전에 자신이 소유한 process group을 정리하고 출력 drain을 끝낸 뒤
transport를 닫습니다. 별도 process group의 backend 서버와 agent는 중지하지 않습니다.

`protected_paths`는 admission 시 경로 겹침을 확인합니다. project, working
directory 또는 original repository가 양방향으로 보호 경로와 겹치면 mutation을
거부하고 관찰만 허용합니다. 실행 중인 process의 파일 접근을 제한하거나
filesystem confinement을 제공하지 않으며 sandbox가 아닙니다. Native agent는
실행 계정의 권한, 도구, 네트워크 접근을 그대로 가집니다.
tmux의 working directory는 설정된 project 경로가 아닌 검증된 process의 실제
canonical cwd입니다. 조회·입력 전에 다시 확인하며, cwd를 확인할 수 없으면
대상을 숨기고 후속 상호작용을 거부합니다.
Native agent의 승인 정책은 별도로 유지됩니다. OMP 쓰기 승인 smoke는
`--approval-mode=always-ask`와 owner-only YAML의 `tools.approval.write: prompt`를
사용하세요. `--approval-mode=write`는 해당 등급을 허용하지 승인 UI를 요구하지
않습니다. 화면을 읽고 사용자가 명시적으로 선택한 응답만 전달하세요. Herdr prompt
문자열은 제출 중 같은 host의 process argv에 보일 수 있으므로 credential을 보내지 마세요.

독립 [`dotunnel-adapter-runner`](../adapter_runner/README.md)는 별도 계약이며 기본
도구 일곱 개만 사용합니다. 이 runner에는 Herdr·Orca·tmux·provider adapter가
포함되지 않으며 Orca는 core supervision에도 포함되지 않습니다.

## 8. Secret을 공개하지 않는 개발

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

## 9. 유지보수자 draft 릴리스

source 변경은 feature branch와 PR로 반영합니다. public `main`은 GitHub Actions의 `Secret scan`, `Python 3.11`, `Python 3.13` 성공과 최신 base, 리뷰 대화 해결을 요구하며 관리자에게도 적용됩니다. main 직접 push·force-push·브랜치 삭제는 금지합니다.

릴리스 workflow는 **draft만** 준비합니다. 배포할 정식 package 버전을 main에 merge하고 그 정확한 commit의 main CI 성공을 확인한 뒤 일치하는 stable tag를 push하세요. 예를 들어 main의 버전이 `0.1.5`일 때:

```sh
git fetch origin main
git tag v0.1.5 origin/main
git push origin v0.1.5
```

tag/package 불일치, main 이력 밖 source, 성공한 main CI 부재와 기존 release는 거부합니다. 읽기 전용 job이 universal wheel을 빌드·검증하고 크기/SHA를 고정한 `install.sh`, `SHA256SUMS`, source-SHA manifest를 생성합니다. 별도 draft 첨부 job만 저장소 write 권한을 사용하며 PAT·운영자·worker credential을 전달하지 않습니다. 전체 asset을 검토한 뒤 GitHub Releases에서 사람이 Publish하세요. 첨부 실패는 공개되지 않은 draft로 남고 workflow는 실패합니다. 기존 asset은 덮어쓰지 않습니다.

tag 생성이나 Release 변경 없이 준비 과정을 확인하려면:

```sh
gh workflow run release.yml --ref main -f dry_run=true
```

해당 run의 summary와 검증 artifact를 확인하세요. dry-run은 준비 과정 검증이며 실제 draft 첨부나 공개 검증이 아닙니다. draft는 updater의 최신 안정 릴리스가 아니며 수동 Publish 후에만 배포 대상이 됩니다. 여기서 `gh`는 유지보수자 도구일 뿐 설치·updater 요구 사항이 아닙니다.

각 준비된 릴리스에는 해당 wheel을 고정한 설치 스크립트가 포함됩니다. front page의 raw `main/install.sh`는 별도로 검토된 pin을 유지합니다. 기본 pin 갱신은 실제 공개 wheel의 byte 수와 SHA를 사용하는 일반 PR로 처리하며 자동 변경하지 않습니다. 이미 공개된 wheel의 checksum을 dry-run 재빌드 checksum으로 바꾸지 마세요.

## 추가 참고

- [English front page](../README.md) · [한국어 front page](../README.ko.md)
- [설계 및 runtime 경계](../DESIGN.md)
- [최소 config 예시](../config.example.json)
- [로고 asset](../assets/dotunnel.png) · [MIT License](../LICENSE)
- [OpenAI Secure MCP Tunnel 공식 문서](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
