# dotunnel

<p align="center"><img src="assets/dotunnel.png" alt="dotunnel: 속이 뚫린 원기둥으로 형상화한 터널" width="840"></p>

[English](README.md) | **한국어**

`dotunnel`은 Linux 서버에서 실행하는 자체 호스팅 stdio MCP 서버이자
private Secure MCP Tunnel 연결 도우미입니다. 기본 API는 workspace file/task
도구 일곱 개를 제공합니다. 운영자가 Herdr 및/또는 tmux 대상을 supervision
registry에 명시적으로 등록하면 공통 `agent_*` 도구 여덟 개가 추가됩니다.
호스팅 서비스나 공개 MCP endpoint가 아닙니다.

| 구분 | 포함 내용 |
|---|---|
| 기본 | 제한된 workspace file/task MCP 도구 일곱 개 |
| 선택 CLI 작업 | 별도 설치한 Codex·Claude Code·OMP CLI용 격리 작업 |
| 선택 supervision | 명시적으로 등록한 Herdr 및/또는 tmux 대상용 공통 `agent_*` 도구 여덟 개 (활성화 시 총 15개) |
| 선택 runner | 별도 설치하는 [공통 JSON-stdio adapter runner](adapter_runner/README.md); 기본 도구 일곱 개를 사용 |

## 요구사항

- root가 아닌 Linux 계정, Python 3.11 이상과 `python3`, `venv`, `pip`.
- 한 줄 설치에는 `curl`, `sha256sum`이 필요하며 `uv`는 필요하지 않습니다.
- ChatGPT/Platform 자격과 권한, OpenAI Tunnel ID와 제한된 runtime key,
  공식 `tunnel-client`는 별도 준비해야 합니다. `dotunnel`은 권한을 부여하거나
  이를 대신 제공하지 않습니다.

## 설치

GitHub 로그인 없이 현재 릴리스를 설치합니다.

```sh
curl -fsSL https://raw.githubusercontent.com/junited31/dotunnel/main/install.sh | sh
```

설치 스크립트는 고정된 wheel을 검증한 뒤
`$HOME/.local/share/dotunnel/venv`에 설치하고
`$HOME/.local/bin/dotunnel`을 제공합니다. piped stdin에서 setup을 실행하지
않으며, 공식 client 설치나 계정·권한·key·Tunnel 설정·shell startup·서비스
변경도 하지 않습니다. 기존 설치 경로나 무관한 launcher를 덮어쓰지 않습니다.
기존 설치에는 `dotunnel update`를 사용하세요. `dotunnel`을 찾지 못하면
`$HOME/.local/bin`을 직접 `PATH`에 추가하거나 절대 경로로 실행하세요.

wheel을 직접 내려받으려면 [수동 설치 안내](docs/guide.ko.md#수동-설치)를 참고하세요.

## 설정

setup은 대화형 터미널에서 실행해야 합니다. 공식 client를 별도로 설치하고
checksum을 검증하세요. 계정 권한, Tunnel ID, Restricted runtime key도 직접
준비해야 합니다. `dotunnel`은 이를 대신 만들 수 없습니다.

```sh
"$HOME/.local/share/dotunnel/venv/bin/dotunnel" setup --directory "$HOME/.dotunnel-setup"
```

setup은 private profile/config와 입력한 key를 별도 workspace 밖에 저장합니다.
workspace는 `tasks: []`로 시작합니다. 계정 격리, private 설치와 ChatGPT 연결은
[상세 안내](docs/guide.ko.md)를 참고하세요.

## 명령

| 명령 | 용도 |
|---|---|
| `dotunnel help` | 사용법 표시 |
| `dotunnel setup` | Tunnel 설정 생성 또는 선택 CLI 연동 설정 |
| `dotunnel doctor` | 설정·client·연결 상태 읽기 전용 진단 |
| `dotunnel update` | 최신 안정 release 확인 후 대화형 업데이트 |
| `dotunnel serve --config PATH` | trusted config로 stdio MCP 서버 실행 |
| `dotunnel supervision init --config PATH` / `reinit` | 선택 supervision 상태를 명시적으로 초기화·교체 |

## 선택 Herdr/tmux agent supervision

trusted config에 고정 `supervision` registry를 넣고 private 상태를 명시적으로
초기화해야 supervision이 활성화됩니다. 두 backend 중 하나 또는 둘 다 설정해도
공통 `agent_*` 도구 여덟 개만 추가되므로 MCP 도구는 총 15개입니다. 고정
project와 profile이 사용할 수 있는 connection을 제한합니다. Herdr session과
tmux socket은 함께 등록할 수 있습니다. 기본 connection은 새 시작에만 사용하며
broadcast나 자동 fallback을 허용하지 않습니다. 승인, handle, receipt와 identity
제한은 [상세 안내](docs/guide.ko.md#7-선택-herdrtmux-agent-supervision)를 참고하세요.

[0.1.5](https://github.com/junited31/dotunnel/releases/tag/v0.1.5)에 포함됩니다.
패키지 설치만으로 supervision이 설정되거나 활성화되지는 않습니다.

## 선택 공통 adapter runner

[독립 runner](adapter_runner/README.md)는 기존 일곱 file/task MCP 도구를
사용합니다. 검토한 source에서 별도 설치하고 고정 작업 하나를 명시적으로
등록해야 하며, 기본 설치·setup은 이를 활성화하지 않습니다. mutation은 정확한
요청과 private registry profile에 묶인 로컬 대화형 승인이 필요합니다. durable
replay는 재실행 없이 저장한 결과를 반환하며, 불명확한 효과는
`outcome_unknown`으로 유지합니다.

이 runner에는 Herdr·Orca·tmux·provider adapter가 포함되지 않습니다. Core
supervision은 별도 기능으로 설정된 Herdr/tmux backend를 지원하며 Orca 지원은
포함하지 않습니다.

## 안전

- root가 아닌 계정으로 실행하세요. 광범위한 그룹·sudo가 없는 전용 계정을
  권장합니다. 프로젝트는 계정을 만들거나 권한을 변경하지 않습니다.
- 설치 프로그램, trusted 설정/credential, writable workspace를 분리하세요.
  초기 `tasks: []`이며 credential은 workspace 밖에 저장됩니다.
- 고정 작업은 MCP 실행 계정의 전체 OS 권한으로 실행됩니다. 고정 명령이나
  workspace는 sandbox가 아니므로 코드와 side effect를 검토하세요.
- stdio MCP에는 별도 사용자 인증이 없습니다. 접근 주체를 제한하고 허용 파일과
  작업 결과에 민감 정보가 없는지 확인하세요.
- 선택 CLI 작업에는 Bubblewrap이 필요합니다. native CLI는 같은 사용자로 실행되어
  참조 credential을 읽을 수 있고 허용 내용은 provider로 전송될 수 있습니다.
  candidate는 자동 적용·검증되지 않습니다.
- `curl | sh`는 저장소의 설치 스크립트를 현재 사용자 권한으로 실행합니다.
  스크립트를 신뢰·검토하세요. wheel checksum이 shell 스크립트까지 무조건
  신뢰해도 된다는 뜻은 아닙니다.
- source 개발 시 [커밋 전 secret 검사](docs/guide.ko.md#8-secret을-공개하지-않는-개발)를 켜고 runtime/key 파일을 checkout 밖에 두세요.

[상세 안내](docs/guide.ko.md) · [설계](DESIGN.md) ·
[config 예시](config.example.json) · [라이선스](LICENSE)
