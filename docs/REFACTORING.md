# План рефакторинга

Документ описывает **ещё не сделанную** работу по структуре кодовой базы. Всё, что
перечислено ниже, разбито на фазы так, чтобы каждая фаза была одним коммитом,
который можно откатить целиком, и чтобы после каждой фазы дерево собиралось, а
поведение не менялось (кроме фаз, где смена поведения — это и есть цель).

Проект в статусе `5.0.0-alpha`: жёстких контрактов, которые нельзя менять, нет.
CLI, форма `--json` и раскладка модулей меняются свободно — важно лишь, чтобы
кодовая база становилась меньше и понятнее, а документация не описывала форму,
которую бинарник уже не выдаёт.

## 1. Инварианты проекта

Их нельзя нарушать ни в одной фазе:

* **Только Rust.** Никаких крейтов с C/C++ сборкой (`openssl`, `curl-sys`,
  `ring`-совместимые обёртки) — целевые устройства это роутеры
  `mipsel-unknown-linux-musl` без динамического линкера.
* **Бюджет памяти.** Релизный бинарник 3–6 МБ (`opt-level = "s"`, `lto = true`,
  `codegen-units = 1`, `panic = "abort"`, `strip = true`), RSS 3–6 МБ. Никаких
  неограниченных аллокаций, никаких временных файлов без явного аргумента CLI.
* **Классификация стадий.** Каждая проба TCP/TLS обёрнута в `DpiProbeStream`;
  сброс или EOF после ClientHello — это `DpiStatus::TlsRst`, таймаут на connect —
  `DpiStatus::SynDropped`.
* **Бейджи и протоколы — латиницей** во всех языках (`OK`, `BLOCKED`, `TLS RST`,
  `SNI`, `ClientHello`); переводятся только заголовки, баннеры, меню и `--legend`.
* **Все тексты интерфейса — в `dpi-core::i18n`** (четыре блока: `En`, `Ru`,
  `Zh`, `Fa`); ни одна строка для человека не пишется на месте вызова.
* **TUI рисуется только через `render::frame_repaint`** с `render::frame_home`:
  ручное добивание строки до фиксированной ширины запрещено (CJK-шрифт считает
  `│`, `↑`, `←` за две колонки), экран не очищается и курсор не уводится в `(0,0)`.

## 2. Что уже сделано

| Коммит | Содержание |
| --- | --- |
| `9339a6b` | Общие хелперы в одно место, `main.rs` 1778 → 670 (появились `runner.rs`, `terminal.rs`, `menu.rs`) |
| `3fc734a` | Один `dial_tcp`, именованные загрузчики целей, системные запросы ушли в `spawn_blocking` |
| `60c682a` | Задокументировано отклонение по версиям TLS в закреплённом ClientHello |
| `83ca592` | Меню и экран теста 6 рисуются общим `panel_to_string`, таблица тестов берётся из `Messages::menu_test_label` |
| `2abd399` | README и правила больше не подают форму `--json` и бейджи как замороженный контракт |
| `1722e16` | ~150 комментариев описывают поведение, а не «зеркало» выведенного из эксплуатации прототипа |

## 3. Целевая слоистость

Сейчас в ядре три цикла, у каждого ровно один виновный импорт:

* `net → dns` — `net/netinfo.rs:21` (`query_doh_txt`);
* `dns → probe` — `dns/availability.rs:23` (`fake_ip_type`);
* `dns → classify` — `dns/availability.rs:98-99` (обе строки внутри `availability`).

Цель — ацикличный граф:

```
classify  ←  net  ←  dns  ←  probe
   (лист: стадии и вердикты)   (7 диагностических тестов)
config, profile, i18n — сбоку; бинарник — только представление и оркестрация
```

## 4. Фазы

### P0 — Референсный снимок вывода

* Снять `--json` для `-t 1`, `-t 2 -d example.com`, `-t 5` в файл и набор ключей
  (`jq 'paths(scalars)|join(".")'`) — это **эталон для глаз**, не контракт.
* Зачем: P2.5 и P2.6 меняют форму `detail` и форму JSON; сравнение должно быть
  осознанным, а не побайтовым.
* Риск: нет. Ничего не блокирует.

### P1 — `net/version.rs` уходит из ядра в бинарник

* Что: 244 строки — `fetch_latest_version` (GitHub Releases API), `version_badge_lang`,
  `ReleaseInfo`, `CURRENT_VERSION`, `is_newer` → `crates/dpi-detector/src/update.rs`.
* Почему: это сервисная утилита уровня приложения, и это **единственный** модуль
  ядра, который вообще использует `i18n` (`net/version.rs:1,160`), а также тянет
  `netinfo::http_get_text`.
* Цена: два импорта в бинарнике (`main.rs:9`, `menu.rs:17`) и правка `net/mod.rs`.
* Проверка: гейт + живой запуск меню (бейдж версии в баннере).

### P1.5 — Публичная поверхность ядра

Аудит показал ~63 `pub`-элемента без единой ссылки вне своего файла. У библиотечного
крейта такие вещи не ловятся компилятором, поэтому чистка + защита от повторения:

* Удалить (или достроить и позвать из теста 2) `probe/tls.rs` — 196 строк,
  `probe_tls_domain`, `probe_tls_domain_default`, `is_suspicious_redirect`;
  сейчас живут только в реэкспорте `probe/mod.rs:12`.
* Понизить до `pub(crate)` либо удалить: `net/version.rs:154` `version_badge`
  (зовётся только из своего теста), 27 неиспользуемых реэкспортов `dns/mod.rs:10-17`
  (живой через реэкспорт — один, `parse_socks_proxy`),
  `net/tls.rs` `create_insecure_dpi_tls_config_tls13/tls12`,
  `probe/connector.rs` `new_insecure_tls13`/`new_insecure_tls12`/`new_verifying`,
  `classify/stream.rs` `ProbeState` и `DpiProbeStream::{into_inner,get_ref,get_mut}`,
  `dns/wire.rs` `QTYPE_NS/SOA/PTR/MX`, `net/cert_compression.rs` `covers` (только тесты),
  `i18n` `Language::{code,name,is_rtl}`,
  `profile` `default_resolvers`/`default_doh`/`blockpage_signatures` (только тесты),
  `lib.rs` алиасы `PhaseSwitch`/`BlocksSwitch`.
* Защита: включить `#![warn(unreachable_pub)]` в `dpi-core/src/lib.rs` и разобрать
  выдачу, чтобы поверхность снова не расползлась.

### P2 — Тест 1 переезжает из `dns/` в `probe/`

* `dns/availability.rs` (1146 строк, тест 1) → `probe/dns_avail.rs`; `dns/` остаётся
  чистым протоколом (`wire`, `udp`, `doh`, `dot`, `socks`, `resolve`, `types`).
* Убирает рёбра `dns → probe` и `dns → classify`.
* Цена: 9 импортов в бинарнике (`render.rs`, `runner.rs`) и `dns/mod.rs:11`.

### P2.5 — `detail` из строк в тип (приоритет)

Сегодня классификация **парсит прозу**: `i18n/details.rs:32,33,51` режет деталь по
`" at "` и снимает `"KB"`, `probe/whitelist.rs:86,225` проверяет
`detail.contains(DET_AT_KB_MARKER)`, а сборка идёт через
`format!("{}{}{}{}", …, DET_AT_KB_MARKER, kb, DET_KB_SUFFIX)` в
`probe/tcp16.rs:177,260,273,286` и `probe/domains.rs:238,241,401,404`.
`DET_*` встречаются в 276 строках, а `classify/constants.rs:44-46` прямо называет
маркер частью wire-формата.

* Целевое: `enum Detail` в `classify` (`TlsDrop`, `ReadTimeout { kb }`,
  `Tcp16Range { kb }`, `Spoof(…)`, `CertIssue(…)`, `DnsError(…)`, …) с `code()` для
  JSON и отображением через `i18n::detail_text(Detail)` — исчерпывающий `match`
  вместо runtime-теста покрытия.
* Эффект: сравнение вариантов вместо строк, snake_case-токен в JSON, проза только
  в i18n; `ALL_DET_DETAILS` и `i18n/details.rs` сокращаются до таблицы вариантов.
* Риск: средний (задевает все пути ошибок). Проверка: гейт + живой `-t 2/3/4/5`
  с diff по `--json` против снимка P0.

### P2.6 — Типизированный `--json`

* Сейчас `runner.rs` собирает вывод вручную — 14 сайтов `serde_json::json!`.
  Отчёты ядра уже структуры (`DnsAvailReport`, `DomainStats`, `BurstReport`,
  `TelegramFullReport`), `DpiStatus` уже `Serialize` (`classify/types.rs:30-31`).
* Целевое: `#[derive(Serialize)]` на отчёты + одна обёртка верхнего уровня;
  `status` и `detail` уходят в JSON через serde.
* Эффект: схема описана в одном месте; класс ошибок «поле есть в таблице, но нет
  в JSON» исчезает.

### P2.7 — `i18n` по файлам языков

`i18n/mod.rs` — 1739 строк, `Messages` — 212 полей × 4 блока. Разложить на
`i18n/{mod,en,ru,zh,fa,details}.rs`. Тест паритета полей сохраняется: добавление
языка — это один новый файл.

### P3 — Разрезать `render.rs` (3013) и `menu.rs` (1531)

* `tui/backend.rs` — VT/Win32 FFI, `output_str`, `frame_home`, режимы (`ascii`,
  `plain`, `has_vt`).
* `tui/widgets.rs` — панели и рамки (`panel_with`, `box_chars`, `asc`, `cell_color`,
  `status_color`), ширина и перенос (`strip_ansi_len`, `wrap_ansi`), `frame_repaint`.
* `tui/progress.rs` — `LiveProgress`, `Spinner`, `progress_line`, `Refresher`.
* `views/*` — по уже существующим секционным маркерам `// ─── Test N ───`
  (`netinfo`, `dns`, `domains`, `tcp`, `whitelist`, `telegram`, `burst`, `summary`).
* `menu.rs` → `tui/screens/{main,burst,legend,post_run}.rs` + `tui/input.rs`
  (нормализация раскладок и `nav_key`).
* Жёстко: математика ширины и `frame_repaint` остаются в одном модуле.
* Заодно P3.5: удалить внутренний markup-слой — 16 сайтов `[green]…[/]`
  (`render.rs:2238-2289`) и конвертер `markup_to_ansi` (`render.rs:2362-2371`):
  писать SGR сразу.
* Проверка: живой TUI в pty (главное меню и экран теста 6) + гейт.

### P4 — Разделить `net/netinfo.rs` (988)

* `net/http_client.rs` — `http_get_text`, `http_get_chain`, `http_get_once`,
  `request_once` (нужны и публичному IP, и Cymru).
* `sysinfo/os.rs`, `sysinfo/bypass.rs` — реестр Windows, адаптеры, маршрут,
  `get_system_dns`, `detect_bypass_tools`, `resolv.conf`/`getprop`.
* Разрывает `net → dns` (`net/netinfo.rs:21`) и делает граф ацикличным.
* Заодно `TCP_NODELAY`: он есть в `net/tcp.rs:32`, `dns/doh.rs:79`, `dns/dot.rs:102`
  и отсутствует в шести голых дозвонах — `netinfo.rs:149`, `telegram.rs:71,191,369`,
  `probe/tls.rs:55`, `dns/socks.rs:110`. Либо ставить везде, либо перестать называть
  его требованием в `net/tcp.rs:22`.

### P4.5 — Свернуть TLS-фабрики

`net/tls.rs` — девять `pub fn create_*`; `probe/connector.rs` — семь конструкторов
(`new_insecure`, `…_tls13`, `…_tls13_with`, `…_tls12`, `…_tls12_with`,
`…_versioned_with`, `new_verifying`). Целевое: один
`TlsProfile { fingerprint, version, alpn, verify }` и один
`RustlsConnector::from(profile)`. Обязательные тесты: `grease_version_leads_supported_versions`,
`bundle_versions_match_their_ja3`, `bundle_versions_match_their_ja4`.

### P5 — `i18n` из ядра в бинарник (ждёт решения)

Плюс: ядро перестаёт возить тексты интерфейса, слоистость становится строгой.
Минус: разрывается связка «константы `DET_*` в ядре ↔ их переводы» (`i18n/details.rs`
импортирует `classify::*`), правятся правила проекта и README.
**Рекомендация:** делать после P2.5 и только если появится второй потребитель ядра.

### P6 — CI-гейт

В `.github/workflows/` сейчас только `release.yml` (матрица на 12 целей, по тегу).
Добавить job `check` на push/PR: `cargo test --workspace`,
`cargo clippy --workspace --all-targets`, `cargo build --locked`.
Отдельным пунктом (по решению) — сравнение вендоренного `vendor/rustls` с текущим
релизом crates.io.

### P7 — Аудит `unwrap()`/`expect()` вне тестов

39 мест в 9 файлах: `profile/mod.rs` 15, `dns/availability.rs` 8, `probe/domains.rs` 5,
`net/tls.rs` 4, `config.rs` 3, `render.rs`/`tcp16.rs`/`http.rs`/`fingerprint.rs` по одному.
При `panic = "abort"` паника убивает прогон целиком: каждый случай либо обосновать
комментарием (инвариант, доказанный конструкцией), либо превратить в `?`/дефолт.

### P8 — `TestKind` вместо 9-бушного кортежа (опционально)

`selection_flags` (`main.rs:34-46`) возвращает девять `bool`; перестановка в такой
кортеж компилируется молча. Ввести `struct TestKind`/битовый набор, потребителей —
`menu.rs`, `runner.rs`.

### P9 — Типизированный конфиг (опционально, продуктовое решение)

1092 строки `config.rs` поверх `serde_yaml`: `sanitize_mapping` (`:426+`), `yaml_str`,
приведение типов, `ConfigWarning`. Слой существует, чтобы принимать «грязные»
ручные конфиги; его удаление сократит ~300 строк, но перестанет принимать то, что
сегодня принимается. Это видимое пользователю поведение — только по явному решению.

## 5. Отклонено (не предлагать снова)

| Предложение | Причина |
| --- | --- |
| Трейт `DiagnosticTask` для всех семи тестов | Сигнатуры и отчёты у тестов разные by design (`check_dns_availability(&AppConfig, Option<PhaseProgress>, usize)` против `burst_targets(&AppConfig, &[BurstTarget], &BurstSettings, usize)`), а шов прогресса и отмены уже есть: `PhaseProgress`/`ProgressTick`/`BlockTick` и языконезависимые `PhaseId`/`ProgressBlock` |
| Переименовать `probe/` в `engine/` и завести слой `protocols/` | Перестановка без границы: в `probe/` шесть движков и три мелких примитива (`connector.rs` 91, `http.rs` 172, `tls.rs` 196) |
| Перенести `probe/connector.rs` в `net/` | Трейт принимает и возвращает `DpiProbeStream`, а `net/` сегодня не знает о `classify` (ноль ссылок) — перенос создаёт новое ребро снизу вверх |
| Перенести `probe/http.rs` в `protocols/` | Потребителей вне проб нет, а перенос разносит поддержку проб по двум слоям |
| `enum DiagnosticVerdict` вместо `DpiStatus` | `DpiStatus` уже enum; типизировать нужно `detail` — это P2.5 |

## 6. Как проверять каждую фазу

```bash
cargo test --workspace
cargo clippy --workspace --all-targets      # ровно 0 предупреждений
```

* Один коммит — одна фаза. Перемещения и правки не смешивать в одном коммите:
  перемещение должно читаться как перемещение.
* `cargo fmt` не запускать: в дереве 48 из 54 файлов с CRLF, rustfmt пишет только
  LF, `cargo fmt --all --check` ругается на 39 файлов — один прогон перепишет и
  переразметит почти всё дерево. Форматировать руками.
* Живая проверка по поверхности: TUI — запуск в pty (меню и экран теста 6);
  CLI — бинарник `release-local` с `--json`; для изменений вывода — diff против
  снимка P0.
* Быстрая сборка для итераций:
  `cargo build --profile release-local --target x86_64-pc-windows-msvc -p dpi-detector`.
* Релизный артефакт собирается только тогда, когда он реально нужен:
  `RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-msvc`.
  `dist/` обновляется по явной просьбе.
