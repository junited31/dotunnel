# dotunnel

[English](README.md) | **한국어**

Linux용 **자체 설치형 stdio MCP 서버**와 private Secure MCP Tunnel 연결 도우미입니다. ChatGPT가 지정한 작업 디렉터리의 파일을 읽고 수정하며, 서버 관리자가 미리 정의한 고정 작업만 실행할 수 있습니다. 공개 HTTP listener나 tmux 같은 터미널 멀티플렉서는 필요하지 않습니다.

```text
사용자의 ChatGPT → 사용자의 Secure MCP Tunnel → 사용자 서버의 tunnel-client
                                                 → stdio MCP → 지정 workspace / 고정 작업
```

각 사용자가 **자기 서버에 설치**하는 도구입니다. 호스팅 서비스, 공개 MCP endpoint, 공개 ChatGPT plugin이 아닙니다. Secure MCP Tunnel 자체도 [공개 plugin 제출/배포용이 아닙니다](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

| 구성 | 포함 |
|---|---|
| 기본 | Tunnel 연결 도우미(`dotunnel setup/doctor`) + 파일·고정 작업 MCP 서버 |
| 선택 | 설치된 Codex·Claude Code·OMP를 격리된 고정 작업으로 연결 |

## 요구사항

- Linux, Python 3.11 이상, 공식 MCP Python SDK 2.2.x(패키지가 `mcp==2.2.0`을 요구).
- 비관리자 Linux 실행 계정. root 실행은 거부합니다.
- **서로 분리된** 프로그램 설치 경로, trusted config, writable workspace.
- 의존성 설치용 PyPI 접근. `uv`를 쓰면 [공식 설치 안내](https://docs.astral.sh/uv/getting-started/installation/)를 참고하세요.
- `dotunnel update`용 GitHub CLI(`gh`)와 로그인.
- ChatGPT 연결은 별도: 개발자 모드 자격, Platform Tunnel 권한, workspace association, Tunnel ID, runtime key, 공식 tunnel-client.
- 선택 CLI 연동에만: Bubblewrap(`/usr/bin/bwrap`)과 설치·로그인된 Codex/Claude Code/OMP. setup이 Bubblewrap을 확인하고, 이 계정이 sudo를 쓸 수 있으면 바로 설치를 제안합니다(`[Y/n]`). 아니면 관리자가 실행할 명령을 안내합니다.

## 1. 실행 계정 선택

터널은 SSH/IAM 로그인이 아닙니다. 파일/작업 권한은 **MCP 프로세스를 실행한 Linux 계정**의 권한입니다. 설치 전에 `id`로 계정의 그룹·권한을 직접 확인하세요. 설치 도구가 기존 권한을 제거해 주지는 않습니다.

### A. 전용 `dotmcp` 계정 — 기본 권장

아래는 **관리자가 변경 내용을 검토·승인한 뒤 따로 실행하는 안내**입니다. 이 프로젝트는 계정을 자동으로 만들지 않습니다.

```sh
getent passwd dotmcp
```

계정이 이미 있으면 덮어쓰지 말고 소유자와 용도를 확인하세요. 없을 때만:

```sh
sudo useradd --user-group --create-home --shell /usr/sbin/nologin dotmcp
sudo -u dotmcp -H mkdir -m 700 /home/dotmcp/workspace
```

sudoers, docker 그룹, 공유 프로젝트 그룹, SSH 로그인 권한을 추가하지 마세요. 프로그램은 `/home/dotmcp/app`, 설정은 `/home/dotmcp/.dotunnel-setup`, workspace는 `/home/dotmcp/workspace`처럼 분리합니다. 관리자 터미널에서 `sudo -u dotmcp -H /bin/sh`로 아래 설치 명령을 실행할 수 있습니다.

### B. 기존 비관리자 계정 지정

그 계정의 터미널에서 설치하고 실행합니다. 다른 기존 계정을 쓰려면 `sudo -u 계정명 -H /bin/sh`에서 설치/실행합니다. 계정의 비밀번호·로그인 설정·그룹을 자동 변경하지 않으며, 다른 프로젝트를 재귀 `chown`하거나 전역 쓰기 권한을 주지 마세요.

**기존 계정에 광범위한 권한(예: docker 그룹)이 있으면 고정 작업도 그 권한을 가집니다. 전용 계정도 완전한 sandbox는 아닙니다.**

## 2. 설치

workspace 안에는 프로그램을 설치하지 마세요. 시스템 Python이나 공유 환경에도 설치하지 마세요. [GitHub Releases](https://github.com/junited31/dotunnel/releases)의 `dotunnel-<버전>-py3-none-any.whl`을 전용 가상환경에 설치합니다. 아래 `VERSION`을 설치할 release 버전으로 바꾸세요.

```sh
umask 077
VERSION=0.1.0
curl -fLO "https://github.com/junited31/dotunnel/releases/download/v${VERSION}/dotunnel-${VERSION}-py3-none-any.whl"
uv venv --python 3.13 ~/app/venv
uv pip install --python ~/app/venv/bin/python --only-binary :all: "./dotunnel-${VERSION}-py3-none-any.whl"
. ~/app/venv/bin/activate
dotunnel help
```

release 페이지에 표시되는 SHA-256과 내려받은 파일의 `sha256sum` 값을 비교하세요. `uv` 없이 `python -m venv`와 `pip install --only-binary :all: ./dotunnel-...whl`도 사용할 수 있습니다. 설치에 키/토큰은 필요하지 않습니다. 이후 업데이트는 `dotunnel update`로 합니다.

## 사용자용 명령

| 명령 | 동작 |
|---|---|
| `dotunnel help` | 전체 사용법. 인자 없는 `dotunnel`은 메뉴를 열지 않고 이 명령을 안내하며 exit 2 |
| `dotunnel setup` | 새 Tunnel 설정 또는 기존 설정의 선택 CLI 연동 활성화/해제 |
| `dotunnel update` | GitHub 최신 안정 release 조회. 새 버전이 있으면 `[Y/n]` 승인 후 현재 venv에 설치 |
| `dotunnel doctor` | config·CLI 연동 metadata·bubblewrap·공식 client doctor·loopback 연결 상태를 읽기 전용 진단 |

사용자가 직접 쓰는 명령은 위 네 개입니다. 아래 엔진 명령은 Tunnel client나 등록된 작업이 실행하며, 평소에는 직접 칠 필요가 없습니다.

| 엔진 명령 | 동작 |
|---|---|
| `dotunnel serve --config PATH [--check-config]` | stdio MCP 서버. 사용자 메뉴를 MCP stdout에 출력하지 않음 |
| `dotunnel cli-job --config PATH` | 등록된 선택 CLI 작업 1회 실행(아래 `cli-job` 절) |
| `dotunnel claude-token --output PATH [--replace]` | Claude 장기 토큰 파일 생성(대화형 터미널) |

`python -m dotunnel ...`도 같은 명령입니다.

### 업데이트

```sh
dotunnel update
```

- 설치 버전과 최신 안정 release 버전(`junited31/dotunnel` GitHub Releases)을 표시합니다. 같으면 최신 상태로 종료하고, 설치 버전이 더 높아도 downgrade하지 않습니다.
- 새 버전이 있으면 `Update now? [Y/n]`을 묻습니다. **Enter/y/yes는 승인**, n/no는 변경 없이 종료합니다. 다른 입력은 다시 묻고, EOF·비대화형 입력은 설치하지 않고 exit 2, Ctrl-C는 exit 130입니다.
- 자동 설치는 **non-root Linux의 non-editable venv 설치**에 한합니다. 소스 checkout·editable·시스템 Python은 수동 업데이트하세요. `uv`가 있으면 `uv pip`, 없으면 현재 interpreter의 pip를 쓰며 의존성은 binary-only입니다.
- release는 `vMAJOR.MINOR.PATCH` 안정 tag와 `dotunnel-MAJOR.MINOR.PATCH-py3-none-any.whl` asset이 있어야 합니다. 다운로드 크기, GitHub가 제공하는 asset SHA-256, wheel의 패키지명(`dotunnel`)·버전을 설치 전에 검증합니다. draft·prerelease는 대상이 아닙니다.
- 조회 실패나 release 부재를 “최신 버전”으로 표시하지 않고 exit 2로 알립니다. 부분 설치의 자동 rollback은 보장하지 않습니다.
- 설정·key·CLI 인증·Tunnel 연결을 변경하지 않고 서비스를 재시작하지 않습니다. 이미 실행 중인 MCP/client는 작업이 끝난 뒤 직접 재시작해야 새 코드를 읽습니다.

### 진단

```sh
dotunnel doctor \
  --directory /home/dotmcp/.dotunnel-setup \
  --tunnel-client /home/dotmcp/bin/tunnel-client
```

doctor는 client나 모델을 시작하지 않고 설정을 변경하지 않습니다. config가 유효해도 live/ready 및 성공한 control-plane poll이 관측되지 않으면 exit 2입니다. client는 PATH에서 찾거나 명시한 절대 경로만 쓰며 현재 디렉터리의 실행 파일을 자동 실행하지 않습니다. 인증 파일 존재/metadata 유효는 provider 인증 성공이 아닙니다.

## 3. 대화형 private Tunnel setup

OpenAI 계정/조직·ChatGPT 개발자 모드 자격과 최소권한 실행 계정을 먼저 준비합니다. [공식 client release](https://github.com/openai/tunnel-client/releases/latest)에서 OS/architecture에 맞는 binary를 직접 설치하고 공식 checksum을 검증하세요. setup은 binary 다운로드, Platform 로그인, Tunnel 생성, 키 발급을 자동 수행하지 않습니다.

```sh
dotunnel setup \
  --directory /home/dotmcp/.dotunnel-setup \
  --tunnel-client /home/dotmcp/bin/tunnel-client
```

기본 디렉터리는 현재 위치의 `.dotunnel-setup`입니다. 새 설정의 부모와 client/CLI 실행 파일·인증 참조의 상위 디렉터리는 root/현재 사용자 소유이며 다른 사용자가 쓸 수 없어야 합니다(trusted-owner sticky `/tmp`는 허용, 일반 group/world-writable·타인 소유 부모·symlink는 거부). 기존 설정에 `dotunnel setup --directory DIR`를 다시 실행하면 아래 선택 연동만 재설정하며 key/profile을 읽거나 덮어쓰지 않습니다. 새 Tunnel/키는 새 디렉터리에 설정하고, 기존 연결을 켜려면 기존 profile의 `run` 명령을 쓰세요.

setup은 한 흐름으로 안내합니다.

1. [Platform Tunnel 설정](https://platform.openai.com/settings/organization/tunnels): 생성/편집은 Tunnels **Read+Manage**. 소유 조직과 대상 ChatGPT workspace association을 함께 설정합니다.
2. Tunnel ID를 입력합니다. ChatGPT 개발자 모드 권한은 별개이며 이 도구가 부여할 수 없습니다.
3. [Runtime API key 발급](https://platform.openai.com/settings/organization/api-keys): **Restricted, Tunnels Read+Use**. Admin key를 runtime에 쓰지 마세요.
4. 실제 터미널에서 키를 숨김 입력합니다. non-TTY/숨김 입력 불가 시 중단하며 키를 채팅·argv·프로필 literal·화면에 출력하지 않습니다.
5. 새 0700 디렉터리와 `workspace/`(0700), `runtime-api-key`·`config.json`·`profile.yaml`(0600)을 생성합니다. 키와 설정은 workspace 밖이며 기본 `tasks: []`입니다. 사용자 지정 경로도 버전 관리에서 제외하세요.
6. 공식 `doctor --json` 결과를 검사합니다. **doctor 구성 성공은 원격 인증 성공이 아닙니다.** 수동 foreground 실행은 `y`를 선택해야 시작하며, 같은 Tunnel에 다른 client가 실행 중이면 시작하지 마세요.
7. 실행을 선택하면 loopback health의 live/ready와 **성공한 control-plane poll**까지 확인한 뒤 [ChatGPT 앱 등록](https://chatgpt.com/plugins)과 같은 Tunnel ID 사용을 안내합니다. 최대 45초 안에 인증 readiness가 없으면 setup이 시작한 client만 종료합니다.

실행을 선택하지 않으면 `NOT CONNECTED`와 비밀 없는 수동 명령을 표시합니다. 실행 중에는 setup 터미널을 열어 두세요. Ctrl-C는 해당 client/process group만 정리하며 앱/Tunnel/key 권한을 취소하지 않습니다. 서비스·자동 시작·계정/권한 변경·public endpoint는 만들지 않습니다. 실패/취소 후 만든 private 파일은 보존되며 재시도에는 새 디렉터리가 필요합니다.

ChatGPT 앱에는 Platform runtime key를 입력하지 않습니다. 연결 방식은 **Tunnel**, 입력은 **Tunnel ID**입니다. 로컬 stdio MCP에는 별도 OAuth가 없습니다. 앱 선택 메뉴 위치는 UI/계정별로 다르며, 선택이 보이지 않으면 등록한 앱 이름과 도구를 명시해 호출을 요청하세요. 서버 client가 실행 중이어야 실제 호출이 됩니다.

### Bubblewrap 확인과 선택 CLI 연동

setup은 구성 doctor 다음에 항상 Bubblewrap을 확인합니다. `/usr/bin/bwrap`이 있는지와 **CLI 작업이 쓰는 격리 namespace를 실제로 만들 수 있는지**를 함께 봅니다. 기본 기능(Tunnel, 파일 도구, 고정 작업)에는 필요하지 않습니다.

- **ready:** CLI가 설치돼 있으면 선택 목록을 엽니다.
- **설치 안 됨, sudo 가능 계정:** 배포판에 맞는 명령(예: `sudo apt-get install -y bubblewrap`)으로 지금 설치할지 `[Y/n]`으로 묻습니다. Enter/y면 같은 터미널에서 실행하고, 필요하면 sudo가 비밀번호를 묻습니다. 설치 후 다시 확인합니다. n이면 설치하지 않습니다. sudo 가능 여부는 비밀번호 없는 `sudo -n true` 또는 `sudo`/`wheel`/`admin` 그룹 소속으로 판단하며, 설치가 실패하면 아래 안내로 넘어갑니다.
- **설치 안 됨, sudo 불가:** 관리자가 실행할 명령을 보여 줍니다. `sudo apt-get install -y bubblewrap`(Debian/Ubuntu), `sudo dnf install -y bubblewrap`(Fedora/RHEL), `sudo pacman -S --noconfirm bubblewrap`(Arch), `sudo zypper --non-interactive install bubblewrap`(openSUSE), `sudo apk add bubblewrap`(Alpine). 모르는 배포판이면 패키지 이름만 안내합니다.
- **설치됐지만 사용 불가:** 커널·AppArmor·컨테이너 정책이 비특권 user namespace를 막고 있습니다. 관리자가 bwrap에 허용해야 하며, 재설치로는 해결되지 않으므로 설치를 제안하지 않습니다.

CLI가 설치돼 있는데 여전히 Bubblewrap이 준비되지 않았으면 setup이 기다립니다. 다른 터미널에서 설치한 뒤 Enter를 누르면 다시 확인하고 같은 실행에서 선택 목록으로 이어집니다. `s`를 입력하면 건너뜁니다. 건너뛰어도 기본 설정은 유지되며, 나중에 `dotunnel setup --directory DIR`로 연동을 켤 수 있습니다. `dotunnel doctor`도 같은 상태와 명령을 보여 줍니다.

**가능하면 sudo가 없는 실행 계정을 쓰세요.** 고정 작업과 CLI 작업은 실행 계정 권한으로 돌기 때문에, sudo 가능한(특히 비밀번호 없는) 실행 계정이면 root까지 닿을 수 있습니다. 바로 설치 기능은 혼자 쓰는 서버를 위한 편의 기능입니다. 공유·외부 노출 서버에서는 관리자 계정에서 한 번만 설치하고(시스템 전체 패키지) 실행 계정은 sudo 없이 두세요.

안전한 PATH 실행 파일이 확인된 CLI만 목록에 나타납니다. 탐지는 CLI를 실행하지 않으며, 설치된 CLI가 없으면 이 단계를 건너뜁니다.

```text
Select installed native CLI integrations
> [ ] Codex
  [ ] Claude Code
  [ ] OMP

↑↓ 이동 · Space 활성화/해제 · Enter 선택 항목 연동 설치 · Esc/Ctrl-C 취소
```

- 이미 설치된 CLI를 다시 내려받지 않습니다. `cli-job` wrapper의 고정 작업을 등록합니다.
- 선택한 backend마다 native runtime 경로, 인증 파일 **참조 경로**, target alias, source root, 허용 파일, editable subset을 입력합니다. source root는 MCP workspace와 분리하고, editable을 비우면 review 전용입니다. Claude는 `/login` 파일이 아닌 장기 토큰 파일이 필요합니다(아래 Claude 절).
- setup은 provider 로그인 성공을 증명하지 않습니다. 실행 시점에도 격리가 불가능하면 작업을 거부합니다.
- 모든 선택을 검증한 뒤 registry를 한 번에 교체합니다. 실패하면 일부 CLI만 활성화하지 않으며, 같은 선택을 반복해도 registry는 바뀌지 않습니다.
- 고정 작업 이름은 `dotunnel-codex`, `dotunnel-claude`, `dotunnel-omp`. 운영자 설정은 `DIR/cli-jobs/<backend>.json`, 호출자 요청은 `workspace/dotunnel-requests/<backend>.json`이며 기본 요청은 review입니다. 등록만으로는 모델을 실행하지 않습니다.
- 해제는 해당 setup-owned task만 제거하고 설정·요청 파일은 보존합니다. 다른 task·key/profile은 바꾸지 않습니다.
- 새 설정에서 선택을 취소하면 만든 private 파일은 보존하고 연결 시작 전 exit 130으로 종료합니다. 기존 설정에서 취소하면 registry는 바뀌지 않습니다.
- 범위 설정은 보안 책임입니다. 현재 backend의 인증/config 참조와 setup 내부 파일은 작업 대상으로 거부하지만 모든 비밀을 탐지하지는 못합니다. 다른 backend의 임의 이름 token 같은 인증 파일·비밀을 허용 목록에 넣지 마세요. 허용한 파일은 CLI와 요청 결과를 통해 ChatGPT로 전달될 수 있습니다.

## 4. workspace와 config

대화형 setup은 workspace/config를 이미 만들어 줍니다. 직접 구성하는 운영자는 새 workspace를 만들고 `config.example.json`을 **workspace 밖**의 `config.json`으로 복사해 `root`를 실제 절대 경로로 수정합니다. 초기 `tasks: []`는 기본 실행 권한 없음입니다.

```json
{
  "root": "/home/dotmcp/workspace",
  "tasks": []
}
```

config는 실행 계정 소유의 regular file이어야 하며 symlink/hardlink 및 group/world 쓰기 권한을 허용하지 않습니다. 새 파일에만 `chmod 600`을 적용하세요. `root`는 존재하는 non-symlink 디렉터리여야 하고 `/`, 실행 계정의 home 자체, MCP 프로그램/설정 파일을 포함하는 경로는 거부됩니다. ancestor symlink, JSON 중복 키, 알 수 없는 필드도 거부합니다. 다른 프로젝트 디렉터리를 선택하지 마세요.

고정 작업은 관리자가 추가합니다.

```json
{
  "root": "/home/dotmcp/workspace",
  "tasks": [
    {
      "name": "verify-access",
      "description": "고정된 설치 확인 메시지 출력",
      "argv": ["/usr/bin/printf", "workspace task ready\n"],
      "cwd": ".",
      "timeout_seconds": 5
    }
  ]
}
```

`argv[0]`은 workspace 밖의 절대 경로, `cwd`는 workspace 상대 디렉터리입니다. 기본 timeout 60초, 최대 300초, 작업은 최대 50개이며 client는 이름만 선택합니다. 호출자가 argv/env/shell/timeout/cwd를 바꿀 수 없고, 알 수 없는 도구 인자는 **작업 시작 전에 거부**됩니다.

**작업을 승인하기 전에 executable·고정 인자·실행되는 코드와 side effect를 검토하세요.** 빌드/테스트나 workspace의 수정 가능한 스크립트 실행은 임의 코드를 실행할 수 있습니다. 디렉터리 지정만으로 OS 권한이 제한된다고 가정하지 마세요. 새 session을 만드는 자식은 process-group 정리를 벗어날 수 있습니다.

### 선택 CLI 작업 상세(`cli-job`)

`dotunnel cli-job --config /절대/운영자-config.json`은 운영자가 승인한 파일만 별도 candidate에 복사해 네이티브 CLI로 검토하거나 수정합니다. MCP 도구·인자는 추가하지 않으며 원본 적용, 테스트 실행, commit/push, 임의 shell은 제공하지 않습니다. `review`는 candidate 전체가 읽기 전용이고, `edit`는 `editable`에 나열한 기존 파일의 변경만 허용합니다. 파일 추가·삭제·보호 파일 수정이나 작업 중 원본/root 치환이 발견되면 결과를 게시하지 않습니다.

Linux 비-root 실행과 `/usr/bin/bwrap`이 필수이며 없으면 거부합니다. 전용 mount/PID namespace, capability 제거, 부모 종료 연동을 적용하고 `/workspace`에는 allowlist 복사본만 마운트합니다. 격리 HOME은 `/home/job`이며 CLI의 쓰기 가능한 임시 상태는 host home과 분리됩니다. 인증 참조는 읽기 전용이므로 refresh 저장이 필요한 상태에서는 실패할 수 있습니다.

OMP 예시(경로는 예시이며 실제 설치 경로로 바꾸세요; config는 workspace 밖 실행 UID 소유 private regular file):

```json
{
  "backend": "omp",
  "workspace": "/home/dotmcp/workspace",
  "request": "cli-request.json",
  "runtime": {
    "executable": "/opt/bun/bin/bun",
    "cli": "/opt/omp/node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js",
    "modules": "/opt/omp/node_modules",
    "config": "/home/dotmcp/.omp/agent/config.yml",
    "auth": "/home/dotmcp/.omp/agent/agent.db"
  },
  "targets": {
    "demo": {
      "root": "/home/dotmcp/projects/demo",
      "files": ["arithmetic.py", "check.py"],
      "editable": ["arithmetic.py"]
    }
  }
}
```

Codex는 `backend: "codex"`와 다음 runtime 필드를 씁니다. `companion`은 실행 파일과 같은 디렉터리의 `codex-code-mode-host`여야 합니다. native `app-server`의 experimental `dynamicTools`/Code Mode와 effective feature 조회를 지원하는 설치본이 필요하며, 불일치하면 `exec`나 shell로 우회하지 않고 거부합니다.

```json
{
  "executable": "/opt/codex/bin/codex",
  "companion": "/opt/codex/bin/codex-code-mode-host",
  "auth": "/home/dotmcp/.codex/auth.json"
}
```

Claude Code는 `backend: "claude"`와 다음 runtime 필드를 씁니다. `executable`은 symlink나 launcher가 아닌 실제 native 설치 파일이며, `oauth_token`은 `claude setup-token`이 발급한 장기 토큰 **하나만** 담은 실행 UID 소유 `0600` 파일입니다. 그룹·기타 권한, symlink, hardlink, 여러 값이 있으면 거부합니다.

```json
{
  "executable": "/home/dotmcp/.local/share/claude/versions/<버전>",
  "oauth_token": "/home/dotmcp/.dotunnel/claude-oauth-token"
}
```

토큰 파일은 실행 UID의 **대화형 터미널**에서 한 번 만듭니다(Claude 구독 필요).

```sh
dotunnel claude-token --output /home/dotmcp/.dotunnel/claude-oauth-token
```

이 명령은 `claude setup-token`을 가상 터미널에서 실행해 화면을 보여 주고, 출력된 토큰 하나를 감지해 새 `0600` 파일로 저장합니다. 감지하지 못하면 숨김 입력으로 붙여넣게 합니다. 기존 파일은 덮어쓰지 않으며 교체는 `--replace`로 원자적으로 수행합니다. 토큰은 인자로 받지 않고 값을 다시 표시하지 않습니다. 실행 시 부모가 토큰을 bubblewrap 프로세스의 환경변수 `CLAUDE_CODE_OAUTH_TOKEN`으로만 전달하며 argv나 mount에는 넣지 않습니다. 같은 UID의 Claude는 이 값을 읽을 수 있으므로 비밀 보호 경계가 아닙니다. 유출되면 Claude 계정에서 폐기하고 새로 발급하세요. `claude auth status`의 `loggedIn: true`만으로 서버 인증 성공을 판단하지 마세요.

Claude는 `--safe-mode --restricted`와 고정 파일 도구만 사용합니다(`review`: `Read`, `edit`: `Read,Edit,Write`). `--bare`나 permission bypass는 쓰지 않으며 host settings/hooks/skills/plugins/MCP/세션은 마운트하지 않습니다. 단일 최종 `result`의 `is_error: false`·`terminal_reason: "completed"` 등 성공 필드를 모두 검사하며 `subtype: "success"`만으로 성공 처리하지 않습니다. Claude edit는 편집 파일의 최소 부모 디렉터리만 candidate 복사본에서 쓰기 가능으로 마운트하고, 남은 새 항목·삭제·보호 파일 변경은 게시 전에 거부합니다.

관리자가 MCP config에 backend별 **고정 argv**로 task를 등록합니다. 예: `["/home/dotmcp/app/venv/bin/dotunnel", "cli-job", "--config", "/home/dotmcp/omp-cli-job.json"]`. timeout은 native 200초 제한과 정리를 포함하도록 설정하세요(예: 240초). `run_task`는 완료를 기다리지 않으므로 `get_task_result`로 확인합니다.

호출자는 `write_file`로 지정된 request 파일에 아래 세 필드만 기록하고 `run_task(name)`를 **한 번** 호출합니다. 반환된 `result_id`를 보존해 제한된 간격·기한으로 조회합니다. 진행 중인 작업의 request 파일은 덮어쓰지 마세요. target은 등록된 별칭, mode는 `review`/`edit`만 허용하며 instruction은 UTF-8 최대 8 KiB입니다.

```json
{"target":"demo","mode":"edit","instruction":"check.py를 참고해 arithmetic.py만 수정하고 변경 내용을 짧게 보고하세요."}
```

성공 output은 `reviewed` 또는 `candidate_ready`, `report_path`·`report_sha256` 등을 담습니다. target당 최대 32개 UTF-8 regular file, 파일당 64 KiB입니다. 완료 후 `read_file`로 `cli-results/<backend>/<job_id>/report.json`과 report가 열거한 diff chunk(최대 48 KiB)를 읽어 SHA-256을 대조하세요. `candidate_ready`는 **원본에 적용됐거나 문제가 고쳐졌다는 뜻이 아닙니다.** 모델 summary는 검증 증거가 아니며 모든 report의 `verification`은 `not_run`입니다.

네이티브 출력(logical capture 1 MiB)과 실행 시간(200초)은 제한되며 실패 시 raw CLI 로그 대신 고정 진단만 반환합니다. wrapper는 실패한 job을 다시 호출하지 않습니다. 실패 output은 `{"status":"failed","error_code":"NATIVE_FAILED"}`에 다음 필드만 덧붙입니다.

- `native_error_code`: `SANDBOX_UNAVAILABLE`, `NATIVE_UNAVAILABLE`, `TIMEOUT`, `OUTPUT_LIMIT`, `NATIVE_FAILURE`, `INVALID_NATIVE_STREAM`.
- `native_detail`: `AUTH_FAILED`(API 401/403), `RATE_LIMITED`(429), `PROVIDER_ERROR`, `PERMISSION_DENIED`, `UNSUCCESSFUL_RESULT`, `INVALID_RESULT`, `EMPTY_RESULT`, `SUMMARY_TOO_LARGE`, `NO_RESULT`, `INVALID_STREAM`, `EXIT_NONZERO`.
- `native_exit_code`, `native_elapsed_seconds`: 값이 없거나 형식이 맞지 않으면 생략합니다.

OMP JSON은 프레임별로 엄격히 검증하며 누적 진행·도구 본문을 저장하지 않습니다. 보관 한도 1 MiB는 프레임 최대 980,992바이트, 최종 summary 2 KiB, stderr 64 KiB로 나눕니다. 대화 전체를 담는 단일 프레임이 한도를 넘으면 실패합니다. 같은 UID로 실행되는 CLI는 참조한 credential을 읽을 수 있고 provider 네트워크를 공유하므로 credential 비밀성이나 외부 전송 방지를 보장하지 않습니다. 허용 source·instruction·summary·diff 자체에도 민감한 데이터가 있을 수 있습니다.

## 5. 로컬 검증과 foreground 실행

```sh
dotunnel serve --config /home/dotmcp/config.json --check-config
dotunnel serve --config /home/dotmcp/config.json
```

`--check-config`는 구성만 검증하고 작업/터널을 실행하지 않습니다. 두 번째는 stdio 서버이므로 일반 shell에서 메뉴를 출력하지 않으며 MCP client가 stdin/stdout 프로토콜을 사용해야 합니다. 로그는 stderr, stdout은 MCP 전용입니다. tunnel-client의 child로 직접 지정할 때는 설치된 `dotunnel`의 **절대 경로**와 `serve --config ...`를 사용하세요. `dotunnel setup`이 만든 profile은 이 명령을 자동으로 넣습니다.

개발 검증(작은 fixture 테스트):

```sh
python -m unittest discover -s tests -v
```

## 도구와 제한

| 도구 | 동작 |
|---|---|
| `list_files(path=".")` | 즉시 하위 파일/디렉터리 목록, 최대 200개, 최대 1000 entries 검사 |
| `read_file(path)` | UTF-8 파일 내용과 SHA-256, 최대 64 KiB |
| `search_files(query, path=".")` | literal 내용 검색, 최대 100 matches·1000 entries·4 MiB scan |
| `write_file(path, content, expected_sha256=null)` | null이면 새 파일만 생성, 기존 파일은 현재 hash를 제출해야 교체 |
| `list_tasks()` | 허용된 이름/설명 |
| `run_task(name)` | 고정 작업 시작 후 즉시 `running` 상태와 result ID 반환 |
| `get_task_result(result_id)` | 실행 중 또는 최종 결과 조회, 현재 서버 프로세스의 최근 20개 ID |

작업 호출 순서:

1. `run_task(name)`를 한 번 호출하고 `result_id`를 보존합니다. 응답은 `result_id`, `task`, `status: "running"`, `exit_code: null`, `output: ""`, `truncated: false`입니다.
2. `get_task_result(result_id)`를 조회합니다. `running`이면 기다렸다가 같은 ID를 다시 조회하며, 재조회는 작업을 시작하지 않습니다. 무한·고속 polling은 하지 마세요.
3. 최종 상태는 `completed`, `timed_out`, `failed`, `cancelled`입니다. `completed`도 exit code 0을 뜻하지 않으므로 `exit_code`·`output`·`truncated`를 함께 확인하세요. 실행 중에는 partial output이 없습니다.
4. ID는 영구 저장되지 않으며 캐시는 실행 중 ID를 포함해 최대 20개입니다. 서버 재시작이나 캐시 퇴출 후에는 조회할 수 없습니다. 시작 응답을 잃어도 이미 시작된 작업을 자동 재시도하지 마세요.

- 파일 경로는 root 기준 상대 경로입니다. `..`, 절대 경로, symlink, hardlink, FIFO/device/socket, 숨김·credential/private-key 이름은 거부/제외합니다. 보호된 이름에 확장자를 붙인 파일도 차단합니다. 부모 디렉터리가 이미 있어야 하며 mkdir/delete/move/chmod 도구는 없습니다.
- hash 검사는 같은 서버 인스턴스의 쓰기 요청을 직렬화하지만 외부 편집자와의 atomic transaction은 아닙니다. OS/I/O 실패 중 쓰기는 부분적으로 적용될 수 있습니다.
- 작업은 한 번에 하나이며 출력은 UTF-8 기준 16 KiB로 제한됩니다. 초과분은 메모리에 쌓지 않고 drain하며 truncation을 표시하고, terminal control sequence는 제거합니다.
- 작업 stdin은 닫혀 있고 PATH/HOME/LANG의 최소 환경만 전달합니다. 상속된 OpenAI/SSH/cloud credential 환경변수는 전달하지 않으며 HOME은 workspace입니다.
- 같은 process-group 자식은 완료·timeout·서버 종료 시 정리합니다. 시작 응답 뒤에는 요청/조회가 취소돼도 서버 소유 작업이 계속 실행되고, 서버 종료는 새 시작을 막고 시작 중·실행 중 작업의 정리를 기다립니다. 분리된 자식이 pipe를 유지하면 transport를 닫고 직접 자식을 회수합니다. 새 session으로 빠져나간 자식의 종료는 보장하지 않으며 OS CPU/RAM/disk/network sandbox도 아닙니다.
- 숨김/키 파일 이름 제한이 **모든 비밀 제거를 보장하지는 않습니다.** 허용 파일 및 작업 출력에도 코드·프롬프트·개인정보·비밀이 포함될 수 있습니다. stdio MCP에는 별도 사용자 인증이 없으므로 endpoint/runtime 접근 주체를 제한하세요.
- 도구의 read-only/destructive 힌트는 UI 힌트이며 서버 권한 통제가 아닙니다.

## ChatGPT 연결 전 확인

[OpenAI 공식 Secure MCP Tunnel 문서](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)를 기준으로 합니다.

1. 대상 ChatGPT 계정/plan/workspace에서 개발자용 MCP 등록과 **쓰기·실행 도구 지원 여부**를 확인합니다.
2. Platform 조직 권한을 확인합니다. 실행/앱 선택은 Tunnels Read+Use, 생성/편집은 Read+Manage이며 ChatGPT 개발자 모드와 별개입니다.
3. 대상 workspace/organization association과 단일 tunnel을 확정합니다.
4. ChatGPT로 전송될 workspace 파일·작업 출력, 실행 권한, 연결 해제 방법을 검토합니다.
5. 그 후에 [공식 tunnel-client release](https://github.com/openai/tunnel-client/releases/latest)를 받아 checksum을 검증하고 credential을 설정합니다. stdio는 Tunnel ID당 활성 client 하나만 지원합니다.

런타임 key는 Restricted(Tunnels Read+Use)이며 **Admin key가 아닙니다.** 키를 채팅·소스·argv literal·로그에 넣지 말고 실행 child의 환경을 최소화하세요.

연결을 멈추려면 foreground client를 Ctrl-C로 종료하거나, 서비스로 직접 구성했다면 그 서비스를 중지합니다. 이것만으로 기존 권한이 취소되지는 않습니다. 완전 해제에는 앱 disconnect/delete, tunnel association 제거/삭제, runtime key revoke가 필요할 수 있습니다. 이미 ChatGPT로 전달된 데이터는 연결 해제로 회수되지 않습니다. 이 프로젝트는 서비스·자동 시작을 만들지 않으며, 지속 실행이 필요하면 사용자가 자기 서버 정책에 맞게 구성해야 합니다.

## 비밀과 저장소 관리

`.dotunnel-setup/`, runtime key, profile, config, 토큰 파일은 버전 관리와 공유 저장소에서 제외하세요. 이 저장소의 `.gitignore`는 기본 setup 디렉터리와 `.env`·`*.pem`·`*.key`를 제외합니다.

## 라이선스

[MIT](LICENSE)
