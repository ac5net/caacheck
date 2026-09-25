# caacheck

CAA レコード（RFC 8659）の Relevant RRset を求めて、指定した CA が証明書を発行できるかを判定するスクリプトです。
Python 標準ライブラリだけで動き、外部パッケージのインストールは不要です。

## 使い方

```
git clone https://github.com/ac5net/caacheck.git
cd caacheck
python3 caacheck.py <FQDN> <issuer-domain-name> [--wildcard]
```

例

```
python3 caacheck.py developer.okta.com letsencrypt.org
python3 caacheck.py okta.com letsencrypt.org --wildcard
```

DNS は DoH（dns.google）で引きます。`--fixtures <json>` を渡すとネットワークに出ず、
JSON に書いた応答で動きます（テストと再現用）。

## 何をしているか

- RFC 8659 3. のとおり、要求された FQDN から親へ1ラベルずつ登り、最初に見つかった空でない CAA RRset を採用する
- CNAME の追跡はリゾルバに任せる（RFC 6844 のように CNAME 先の木は登らない）
- `issue` / `issuewild` が1つも無ければ「CAA は発行を制限しない」と判定する（3.）
- ワイルドカード要求では `issuewild` が1つでもあれば `issue` を無視する（4.3）
- 空または文法に合わない `issue` 値は「発行禁止」の意思表示として扱う（4.2）
- critical フラグ（Flags=128）付きの未知タグがあれば発行不可（4.5）
- パラメータは `;` で区切り、空白の有無に依存しない

## 主要30ドメインの実測（2026年9月26日）

```
CAA レコードあり                 : 11 / 30
うち issue / issuewild で制限あり : 9 / 30
  制限していない2件 : microsoft.com, softbank.jp（contactemail タグのみ）
DNSSEC 検証済み（AD=true）       : 5 / 30
```

`fixtures/live-2026-09-26.json` は上記の日に dns.google から取得した応答です。
iodef / contactemail のメールアドレスは伏せてあります（テストには不要なため）。

## テスト

```
python3 test_bugs.py
```

ネットワークに出ないのでオフラインで実行できます。
RFC 8659 本文の例（`fixtures/rfc8659-examples.json`）をそのまま判定した結果と、
実データで踏んだ5つの落とし穴（`issue`/`issuewild` が無ければ制限しない、
パラメータ区切りの空白、issuewild の優先、木登りと CNAME、タグの大文字小文字と Flags=128）を
38件のアサーションで確認します。

## 解説記事

RFC 8659 の要件の読み合わせ、30ドメインの結果、落とし穴の経緯はブログに書いています。

https://ac-5.net/security/caa-record-rfc8659-check/

## ライセンス

MIT
