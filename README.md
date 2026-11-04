# AI Dev Security Setup

Скрипт для Ubuntu/Debian, который создаёт отдельного пользователя `ai-dev` и
запускает coding CLI в изолированной среде [Bubblewrap](https://github.com/containers/bubblewrap).
Поддерживаются Claude Code, Kimi Code, Pi и OpenCode.

Сторонние API моделей подключаются через [LiteLLM](https://docs.litellm.ai/) —
локальный OpenAI-совместимый шлюз. Ключи провайдеров остаются на хосте и не
попадают в песочницу.

> Скрипт изменяет системные настройки от имени root: создаёт пользователя,
> правила nftables, ACL, systemd-юниты и лаунчеры. Запускайте его только на
> машине, которую контролируете, и сначала прочитайте раздел
> [«Безопасность»](#безопасность).

## Содержание

- [Что делает скрипт](#что-делает-скрипт)
- [Требования](#требования)
- [Быстрый старт](#быстрый-старт)
- [Параметры запуска](#параметры-запуска)
- [Как пользоваться](#как-пользоваться)
- [LiteLLM для сторонних API](#litellm-для-сторонних-api)
- [Безопасность](#безопасность)
- [Обслуживание и удаление](#обслуживание-и-удаление)
- [Устранение неполадок](#устранение-неполадок)
- [Структура репозитория](#структура-репозитория)
- [Разработка](#разработка)
- [Лицензия](#лицензия)

## Что делает скрипт

1. Создаёт системного пользователя `ai-dev` без пароля, login-shell и прав
   sudo.
2. Устанавливает выбранные CLI в `/opt/ai-tools` от имени `ai-dev`, затем
   «запечатывает» рантайм: файлы становятся root-owned, setuid/setgid-биты и
   опасные symlink'и удаляются.
3. Настраивает ACL на общей директории `SHARED_DIR`: владелец и `ai-dev`
   получают доступ `rwX`, остальные локальные пользователи — нет.
4. Создаёт bind-mount alias `SHARED_SOURCE` (по умолчанию
   `/srv/ai-dev-shared`), чтобы `ai-dev` не требовал traverse-доступа к
   домашней директории владельца.
5. Устанавливает nftables-правила: интернет и DNS разрешены, локальная сеть и
   loopback в основном заблокированы. Исключения — OpenCode IPC и локальный
   LiteLLM.
6. Создаёт root-owned лаунчеры `/usr/local/bin/*-secure`, которые запускают
   выбранный CLI внутри Bubblewrap.
7. Генерирует конфиг OpenCode для LiteLLM и файл секретов
   `/home/ai-dev/.secrets/env`.
8. Создаёт owner-side SSH deploy key (приватный ключ не монтируется в
   песочницу).
9. На Ubuntu 24.04+, где unprivileged user namespaces ограничены AppArmor,
   загружает точечный профиль для `/usr/bin/bwrap`.
10. В конце выполняет проверки изоляции: sudo, доступ к домашней директории
    владельца, SSH-ключам, `/etc/shadow`, loopback, DNS/HTTPS и запуск CLI.

## Требования

- Ubuntu 22.04/24.04+ или Debian с systemd, apt и nftables.
- Запуск от root: `sudo`.
- У владельца (пользователя, от чьего имени вы запускаете скрипт) должны быть
  права sudo — лаунчеры используют `sudo -u ai-dev`.
- `SHARED_DIR` — существующая директория **внутри домашней директории
  владельца**, абсолютный путь без пробелов и спецсимволов. Разрешены символы
  `A-Z a-z 0-9 . _ / -`.
- Доступ в интернет для apt и официальных install-скриптов CLI.
- Python 3 (используется для генерации конфигов и проверок).
- Для Pi скрипт сам скачивает и проверяет по SHA256 Node.js 22 под архитектуру
  машины.

Скрипт рассчитан на одну рабочую станцию с одним владельцем. Это не
многопользовательская платформа и не замена виртуальной машине.

## Быстрый старт

```bash
git clone https://github.com/QNester/ai-dev-security-setup.git
cd ai-dev-security-setup

sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh
```

Скрипт интерактивно попросит выбрать CLI:

```text
1) Claude Code
2) Kimi Code
3) Pi
4) OpenCode
```

Можно ввести номера или имена через пробел/запятую. По умолчанию выбран
Claude Code.

Неинтерактивный запуск:

```bash
sudo SHARED_DIR=/home/alice/projects \
  bash setup-ai-sandbox.sh --cli claude,opencode --yes
```

После установки:

```bash
# Ключ локального LiteLLM (подробнее ниже)
sudo -u ai-dev nano /home/ai-dev/.secrets/env

cd /home/alice/projects
claude-secure        # или kimi-secure, pi-secure, opencode-secure
```

При первом запуске CLI попросит пройти авторизацию. Учётные данные сохраняются
в `/home/ai-dev`, а не в домашней директории владельца.

### Что произойдёт при установке

- Будут установлены пакеты: `bubblewrap`, `acl`, `nftables`, `curl`,
  `ca-certificates`, `git`, `openssh-client`, `python3`, `file` и другие
  утилиты.
- Официальные install-скрипты CLI будут скачаны по HTTPS и выполнены **от
  имени `ai-dev`**, не от root.
- Пользователь `ai-dev` получит primary-группу `ai-dev` и только
  supplementary-группу `ai-dev-share`; пароль и login-shell отключены.
- В `/etc/fstab` появится запись для bind-mount alias, в nftables — отдельные
  таблицы `ip ai_dev_isolation` и `ip6 ai_dev_isolation`, в systemd — юнит
  `ai-dev-isolation.service`.

## Параметры запуска

```text
sudo bash setup-ai-sandbox.sh [--cli LIST] [--skip-cli] [--uninstall] [--yes]
```

| Флаг | Описание |
| --- | --- |
| `--cli LIST` | Список CLI через запятую или пробел: `claude`, `kimi`, `pi`, `opencode` (также принимаются номера `1`–`4`). Если не указан, скрипт спросит интерактивно. |
| `--skip-cli` | Не скачивать и не обновлять CLI, сохранить текущий набор. Используется для перегенерации конфигов, ACL и firewall. |
| `--uninstall` | Удалить системную интеграцию, ACL и лаунчеры. Пользователь `ai-dev`, его home и файл секретов сохраняются. |
| `--yes`, `-y` | Не задавать вопросов. Обязателен для неинтерактивного запуска. |
| `-h`, `--help` | Показать встроенную справку. |

### Переменные окружения

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `SHARED_DIR` | — (обязательна) | Общая директория с проектами. Должна находиться внутри home владельца. |
| `AI_USER` | `ai-dev` | Имя изолированного пользователя. |
| `OWNER_USER` | `$SUDO_USER` или `$USER` | Владелец, от чьего имени запускаются лаунчеры. |
| `OWNER_HOME` | home владельца | Домашняя директория владельца. |
| `SHARED_SOURCE` | `/srv/ai-dev-shared` | Bind-mount alias для `SHARED_DIR`. Должен не пересекаться с `SHARED_DIR`, home'ами и системными путями. |
| `OWNER_SSH_KEY` | `$OWNER_HOME/.ssh/ai-dev-deploy` | Путь к owner-side deploy key. Приватный ключ не монтируется в sandbox. |
| `AI_SECRETS_FILE` | `/home/ai-dev/.secrets/env` | Файл секретов, который загружается внутри песочницы. |
| `MAX_REVIEW_BYTES` | `1048576` | Максимальный размер файла для `ai-review-file`. |
| `LITELLM_BASE_URL` | `http://127.0.0.1:4000/v1` | OpenAI-совместимый endpoint LiteLLM. |
| `LITELLM_MODELS` | автоопределение | Список model ID через запятую/пробел. |
| `LITELLM_DEFAULT_MODEL` | первый из списка | Модель по умолчанию для OpenCode. |
| `LITELLM_ENV_FILE` | `./litellm.env` рядом со скриптом | Файл, из которого читаются **имена** ключей провайдеров. Скрипт никогда его не source'ит. |

Пример с явными моделями:

```bash
sudo SHARED_DIR=/home/alice/projects \
  LITELLM_BASE_URL=http://127.0.0.1:4000/v1 \
  LITELLM_MODELS="anthropic/claude-sonnet-4-5,openai/gpt-4o" \
  LITELLM_DEFAULT_MODEL=anthropic/claude-sonnet-4-5 \
  bash setup-ai-sandbox.sh --cli opencode --yes
```

## Как пользоваться

### Лаунчеры

После установки доступны команды:

| Команда | CLI |
| --- | --- |
| `claude-secure` | Claude Code |
| `kimi-secure` | Kimi Code |
| `pi-secure` | Pi |
| `opencode-secure` | OpenCode |
| `ai-review-file` | Статический review файла через Claude Code (только если выбран Claude Code) |

Запускайте их из домашней директории владельца:

```bash
cd /home/alice/projects/my-app
opencode-secure
```

Лаунчер стартует в текущей директории, если она находится внутри
`SHARED_DIR`; иначе — в корне `SHARED_DIR`. Для запуска может потребоваться
пароль sudo.

Внутри песочницы:

- рабочая директория `SHARED_DIR` доступна на запись;
- `/home/ai-dev` доступен на запись;
- `/tmp` — это отдельная директория `/var/lib/ai-sandbox/tmp`;
- `/usr`, `/opt/ai-tools` и минимальный набор `/etc` доступны только на
  чтение;
- домашняя директория владельца, его `.ssh` и остальные файлы хоста
  недоступны;
- SSH-ключей и agent forwarding нет;
- автообновление и телеметрия отключены там, где CLI это поддерживает.

### Review файла (только Claude Code)

```bash
ai-review-file /home/alice/projects/my-app/untrusted-script.sh
```

Команда монтирует файл read-only в `/review`, не загружает секреты и
ограничивает инструменты Claude Code только чтением. Модель всё равно получает
содержимое файла, а вердикт `SAFE` не является разрешением на выполнение.
Нужен Claude Code v2.1.248 или новее (используется `--restricted`).
Максимальный размер файла задаётся `MAX_REVIEW_BYTES`.

## LiteLLM для сторонних API

### Зачем нужен LiteLLM

Политика проекта: **доступ к сторонним API моделей идёт через LiteLLM**. Это
даёт:

- единый OpenAI-совместимый endpoint для OpenCode и других CLI;
- ключи Anthropic, OpenAI, Google, OpenRouter и т.д. остаются на хосте, а не в
  песочнице;
- возможность выдавать агенту отдельный virtual key с бюджетом и лимитами
  вместо master key;
- централизованное переключение моделей и провайдеров.

Схема:

```text
┌──────────────────────────────┐        ┌──────────────────────────┐
│ sandbox (ai-dev)             │        │ host                     │
│  OpenCode / другой CLI       │        │  LiteLLM 127.0.0.1:4000  │
│  LITELLM_API_KEY=sk-...      │───────▶│  litellm.env             │
└──────────────────────────────┘  HTTP  └────────────┬─────────────┘
                                                     │
                                      ┌──────────────┼──────────────┐
                                      ▼              ▼              ▼
                                  Anthropic       OpenAI        другие API
```

Скрипт автоматически настраивает LiteLLM только для OpenCode. Остальные CLI
можно подключить к LiteLLM, если они поддерживают OpenAI-совместимый base URL;
их конфигурация выполняется отдельно.

### 1. Установите LiteLLM

Вариант с отдельным venv (рекомендуется):

```bash
python3 -m venv "$HOME/.venvs/litellm"
"$HOME/.venvs/litellm/bin/pip" install --upgrade pip
"$HOME/.venvs/litellm/bin/pip" install 'litellm[proxy]'
```

Если `python3 -m venv` недоступен, установите пакет:
`sudo apt-get install -y python3-venv`.

Или через `pipx`:

```bash
sudo apt-get install -y pipx
pipx install 'litellm[proxy]'
```

Альтернатива — Docker:

```bash
docker run --rm --name litellm \
  --env-file litellm.env \
  -p 127.0.0.1:4000:4000 \
  -v "$PWD/litellm.config.yaml:/app/config.yaml:ro" \
  ghcr.io/berriai/litellm:main-latest \
  --config /app/config.yaml
```

### 2. Создайте конфигурацию

В репозитории есть шаблоны:

```bash
cp litellm.env.example litellm.env
cp litellm.config.example.yaml litellm.config.yaml
chmod 600 litellm.env
```

Заполните `litellm.env`:

- `LITELLM_MASTER_KEY` — ключ самого прокси (придумайте длинную случайную
  строку, например `sk-...`);
- ключи только тех провайдеров, которыми пользуетесь;
- при необходимости `DATABASE_URL` для virtual keys и бюджетов.

`litellm.env` и `litellm.config.yaml` уже добавлены в `.gitignore` — не
коммитьте их.

В `litellm.config.yaml` опишите `model_list`. Имена `model_name` должны
совпадать с model ID, которые вы передаёте в `LITELLM_MODELS` и которые
OpenCode отправляет в LiteLLM. Пример уже содержит Anthropic, OpenAI, Gemini,
OpenRouter, Groq, DeepSeek, xAI, Mistral и Ollama; удалите неиспользуемые
записи.

### 3. Запустите прокси

```bash
./start-litellm.sh
```

Если LiteLLM установлен в venv и не находится в `PATH`:

```bash
LITELLM_BIN="$HOME/.venvs/litellm/bin/litellm" ./start-litellm.sh
```

Скрипт читает `litellm.env` и `litellm.config.yaml`, проверяет наличие ключа и
запускает прокси на `127.0.0.1:4000`. Не запускайте его от root и не
привязывайте к `0.0.0.0`: песочница разрешает только loopback-адрес и порт,
указанные при установке.

Проверка:

```bash
curl -s http://127.0.0.1:4000/v1/models \
  -H "Authorization: Bearer <LITELLM_MASTER_KEY>"
```

### 4. Передайте настройки установщику

По умолчанию скрипт уже использует `http://127.0.0.1:4000/v1`. Если адрес,
порт или модели отличаются:

```bash
sudo SHARED_DIR=/home/alice/projects \
  LITELLM_BASE_URL=http://127.0.0.1:4000/v1 \
  LITELLM_MODELS="anthropic/claude-sonnet-4-5,openai/gpt-4o" \
  LITELLM_DEFAULT_MODEL=anthropic/claude-sonnet-4-5 \
  bash setup-ai-sandbox.sh --cli opencode
```

Если `LITELLM_MODELS` не задан, скрипт определяет модели по именам ключей в
`litellm.env` (файл читается как текст, без выполнения):

| Ключ в `litellm.env` | Модель по умолчанию |
| --- | --- |
| `ANTHROPIC_API_KEY` | `anthropic/claude-sonnet-4-5` |
| `OPENAI_API_KEY` | `openai/gpt-4o` |
| `GEMINI_API_KEY` | `gemini/gemini-2.5-pro` |
| `OPENROUTER_API_KEY` | `openrouter/anthropic/claude-sonnet-4-5` |
| `GROQ_API_KEY` | `groq/llama-3.3-70b-versatile` |
| `DEEPSEEK_API_KEY` | `deepseek/deepseek-chat` |
| `XAI_API_KEY` | `xai/grok-3` |
| `MISTRAL_API_KEY` | `mistral/mistral-large-latest` |
| `OLLAMA_API_BASE` | `ollama/llama3.2` |

Первый найденный ключ становится моделью по умолчанию, если не задан
`LITELLM_DEFAULT_MODEL`. Если модель по умолчанию не входит в список, скрипт
добавит её первым элементом.

### 5. Ключ для песочницы

Песочница не получает ключи провайдеров. Ей нужен только ключ LiteLLM:

```bash
sudo -u ai-dev nano /home/ai-dev/.secrets/env
```

```bash
LITELLM_API_KEY='sk-...'
```

Это значение должно совпадать с `LITELLM_MASTER_KEY` из `litellm.env` **или**
быть отдельным virtual key. Предпочтителен virtual key с бюджетом: master key
даёт доступ ко всем провайдерам, настроенным в LiteLLM. Для virtual keys
LiteLLM требует базу данных (`DATABASE_URL`).

Поддерживается алиас `LITTLE_LLM_API_KEY`: если `LITELLM_API_KEY` пуст, будет
использован он. Файл должен принадлежать `ai-dev` и иметь режим `600`.
`ai-review-file` этот файл не загружает.

Все выбранные CLI получают `LITELLM_API_KEY` внутри песочницы, но OpenCode
дополнительно получает готовый конфиг:

```text
/home/ai-dev/.config/opencode/ai-sandbox-litellm.json
```

Конфиг подключается через `OPENCODE_CONFIG` и не заменяет глобальный конфиг
OpenCode. В нём перечислены модели из `LITELLM_MODELS`/автоопределения.

### 6. Сетевые правила

При установке скрипт разрешает `ai-dev` TCP-доступ только к IPv4-адресу и
порту из `LITELLM_BASE_URL`, если адрес loopback. Остальной loopback
заблокирован. Если LiteLLM слушает не loopback-адрес, исключение не
создаётся, и песочница, скорее всего, не сможет до него достучаться.

После изменения адреса или порта перезапустите установщик с `--skip-cli`,
чтобы перегенерировать правила nftables.

Не размещайте на том же адресе и порту посторонний сервис: агент получит к
нему сетевой доступ.

### 7. OpenCode

OpenCode v2 использует локальный TCP-сервер для связи TUI и API. Скрипт
фиксирует его на `127.0.0.2:49374` и разрешает только этот адрес и порт плюс
настроенный LiteLLM. Не меняйте hostname/port сервиса OpenCode и не
используйте `--standalone`: он выбирает случайный порт, который firewall
заблокирует.

## Безопасность

### Что даёт изоляция

- Отдельный непривилегированный пользователь без sudo, пароля и login-shell.
- Root-owned рантайм CLI; агент не может незаметно изменить свои бинарники.
- Файловая система хоста скрыта, кроме `SHARED_DIR`, `/home/ai-dev`, `/tmp`
  и read-only системных путей.
- Нет доступа к домашней директории владельца, его `.ssh`, `/etc/shadow` и
  owner-side deploy key.
- Сетевые правила блокируют LAN и loopback, кроме явных исключений.
- Секреты не загружаются в режиме review.

### Ограничения

Это важно прочитать до использования:

- Песочница **не является виртуальной машиной** и не защищает от ошибок в ядре,
  Bubblewrap, AppArmor или nftables.
- Агент может изменять всё в `SHARED_DIR`, включая `.git/hooks`, package
  scripts, `.envrc` и задачи редактора. Проверяйте diff'ы перед запуском
  чего-либо вне песочницы. Отдельный clone или отдельная директория под один
  проект безопаснее.
- Существующие `.env` и Git-креденшелы внутри `SHARED_DIR` доступны агенту.
- Файл `/home/ai-dev/.secrets/env` доступен всем инструментам песочницы, кроме
  `ai-review-file`. Агент может его прочитать и изменить. Используйте
  scoped/revocable ключи с лимитами, а не долгоживущие личные токены.
- Сгенерированный конфиг OpenCode и файл секретов лежат в `/home/ai-dev`,
  поэтому агент может их изменить. LiteLLM-ключ также доступен агенту.
  Используйте virtual key с бюджетом, а не master key.
- Песочница намеренно разрешает `ai-dev` доступ к настроенному loopback-адресу
  LiteLLM. Не запускайте на этом адресе/порту другие сервисы и не выставляйте
  LiteLLM в LAN.
- Интернет разрешён. LAN-фильтрация best-effort: возможны NAT hairpin,
  global-IPv6 peers, abstract Unix sockets и другие пути. Для сильной изоляции
  используйте VM или отдельный network namespace с контролируемым прокси.
- DNS разрешён только nameserver'ам из `/etc/resolv.conf` на момент установки,
  порт 53.
- У агента нет SSH-ключа и agent forwarding. Git/SSH выполняйте вне песочницы
  или используйте короткоживущие scoped-креденшелы осознанно.
- Официальные install-скрипты CLI скачиваются по HTTPS, но без независимой
  подписи/контрольной суммы (кроме Node.js для Pi, где проверяется SHA256).
  Если такое доверие неприемлемо, зеркалируйте и пиньте установщики.
- `ai-review-file` подвержен ошибкам модели и prompt injection. Вердикт `SAFE`
  не разрешает выполнение. Модель-провайдер получает содержимое файла.
- Рантайм CLI root-owned и world-readable, потому что песочница работает от
  непривилегированного пользователя. Не кладите креденшелы в installer HOME.
- На Ubuntu 24.04+ точечный AppArmor-профиль разрешает `/usr/bin/bwrap`
  создавать user namespaces. Профиль удаляется при `--uninstall`. Не
  отключайте `kernel.apparmor_restrict_unprivileged_userns` глобально без
  необходимости.
- `--uninstall` снимает ACL и setgid, но не восстанавливает прежнюю группу
  владельца общей директории.

## Обслуживание и удаление

### Обновление CLI и конфигов

Сначала завершите все сессии `ai-dev`:

```bash
pgrep -a -u ai-dev
# завершите процессы или выйдите из песочниц
```

Затем:

```bash
# обновить CLI и перегенерировать всё
sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh --cli claude,opencode

# только перегенерировать конфиги/ACL/firewall, не трогая CLI
sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh --skip-cli
```

Скрипт можно запускать повторно; он поддерживает обновление существующей
установки и меняет набор CLI через `--cli`.

### Проверка состояния

```bash
systemctl status ai-dev-isolation.service
sudo nft list table ip ai_dev_isolation
sudo nft list table ip6 ai_dev_isolation
findmnt /srv/ai-dev-shared
sudo -u ai-dev ls -la /home/ai-dev/.config/opencode
```

### Удаление

```bash
pgrep -a -u ai-dev   # должно быть пусто
sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh --uninstall
```

Что удаляется:

- nftables-таблицы, systemd-юнит и drop-in для nftables;
- AppArmor-профиль `ai-dev-bwrap-userns`;
- лаунчеры `/usr/local/bin/*-secure` и `ai-review-file`;
- `/opt/ai-tools` и `/var/lib/ai-sandbox/tmp`;
- bind-mount alias и запись в `/etc/fstab`;
- ACL, setgid и членство в `ai-dev-share`;
- сгенерированный конфиг OpenCode.

Что сохраняется:

- пользователь `ai-dev` и `/home/ai-dev`;
- `/home/ai-dev/.secrets/env` (проверьте и удалите вручную, если не нужен);
- owner-side deploy key;
- сама общая директория и её файлы.

Скрипт откажется удалять firewall, пока работают процессы `ai-dev`: снятие
правил немедленно ослабило бы изоляцию.

### Deploy key

При установке создаётся ed25519-ключ:

```text
/home/alice/.ssh/ai-dev-deploy
/home/alice/.ssh/ai-dev-deploy.pub
```

Приватный ключ не монтируется в песочницу. Публичный ключ можно добавить как
write-enabled deploy key в GitHub/GitLab:

- GitHub: **Settings → Deploy keys → Add deploy key**, вставить содержимое
  `.pub`, включить **Allow write access**.
- GitLab: **Settings → Repository → Deploy keys**, включить write access.

После установки публичный ключ печатается в выводе скрипта.

## Устранение неполадок

### `Unprivileged Bubblewrap is blocked`

На Ubuntu 24.04+ unprivileged user namespaces ограничены AppArmor. Скрипт
создаёт профиль `/etc/apparmor.d/ai-dev-bwrap-userns`. Проверьте:

```bash
sudo apparmor_parser -Q /etc/apparmor.d/ai-dev-bwrap-userns
sudo aa-status | grep -A2 ai-dev-bwrap
```

Если профиль не загружается, исправьте его или запускайте песочницу в VM.
Системное отключение `kernel.apparmor_restrict_unprivileged_userns=0`
ослабляет защиту для всей машины и не рекомендуется.

### LiteLLM недоступен из песочницы

1. Убедитесь, что прокси слушает loopback и нужный порт:
   `ss -ltnp | grep 4000`.
2. Проверьте, что `LITELLM_BASE_URL` при установке совпадает с реальным
   адресом.
3. Перезапустите установщик с `--skip-cli`, чтобы обновить nftables.
4. Проверьте ключ: `curl` с `Authorization: Bearer ...` должен вернуть список
   моделей.
5. Помните: не-loopback адрес не получит исключения в firewall.

### OpenCode не запускается или не подключается

OpenCode должен использовать `127.0.0.2:49374`. Проверьте:

```bash
sudo -u ai-dev /opt/ai-tools/bin/opencode service get hostname
sudo -u ai-dev /opt/ai-tools/bin/opencode service get port
sudo -u ai-dev /opt/ai-tools/bin/opencode service get env OPENCODE_CONFIG
```

Не используйте `--standalone` и не меняйте порт. Если OpenCode обновился и
перестал совместим с конфигом, перезапустите установку без `--skip-cli`.

### `Stop all ai-dev processes before ...`

```bash
pgrep -a -u ai-dev
# закройте сессии, затем при необходимости:
sudo pkill -TERM -u ai-dev
```

Если процессы не завершаются, проверьте, не остался ли запущенный сервис
OpenCode или установщик CLI.

### Ошибка `SHARED_DIR must ...`

`SHARED_DIR` должен:

- быть абсолютным;
- существовать при установке;
- находиться внутри home владельца;
- содержать только `A-Z a-z 0-9 . _ / -`;
- не пересекаться с home `ai-dev` и `SHARED_SOURCE`.

### Pi не устанавливается на экзотической архитектуре

Поддерживаются `x86_64`, `aarch64`, `armv7l`, `ppc64le`, `s390x`. Для других
архитектур установите Node.js 22 вручную в `/opt/ai-tools/node` или не
выбирайте Pi.

### `sudo: a password is required`

Лаунчеры вызывают `sudo -u ai-dev`. Владелец должен иметь право sudo. Если
нужны неинтерактивные запуски, настройте sudoers осознанно; скрипт сам таких
правил не добавляет.

## Структура репозитория

```text
.
├── setup-ai-sandbox.sh              # основной установщик
├── start-litellm.sh                 # запуск локального LiteLLM
├── litellm.env.example              # шаблон ключей и master key
├── litellm.config.example.yaml      # шаблон model_list для LiteLLM
├── README.md
├── SECURITY.md                      # как сообщать об уязвимостях
├── LICENSE
├── .gitignore
└── .gitattributes
```

## Разработка

Минимальная проверка синтаксиса:

```bash
bash -n setup-ai-sandbox.sh
bash -n start-litellm.sh
```

Если установлен ShellCheck:

```bash
shellcheck setup-ai-sandbox.sh start-litellm.sh
```

Скрипт меняет системные настройки, поэтому тестируйте изменения в одноразовой
VM или контейнере с systemd, а не на рабочей машине. Автотестов в репозитории
нет; установщик сам выполняет проверки изоляции в конце работы.

## Лицензия

MIT. См. [LICENSE](LICENSE).
