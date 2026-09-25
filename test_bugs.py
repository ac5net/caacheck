#!/usr/bin/env python3
"""RFC 8659 の例と、実データで踏んだ落とし穴を、直っていることで確認する

    python3 test_bugs.py

ネットワークに出ない。fixtures/ は 2026-09-26 に dns.google で取得した実応答と、
RFC 8659 本文の例をそのまま置いたもの。
"""
import caacheck as cc

live = cc.make_fixture_lookup('fixtures/live-2026-09-26.json')
rfc = cc.make_fixture_lookup('fixtures/rfc8659-examples.json')
fails = []


def check(name, got, want):
    if got == want:
        print('ok   %s' % name)
    else:
        print('FAIL %s\n       got  %r\n       want %r' % (name, got, want))
        fails.append(name)


def allowed(fqdn, issuer, wildcard=False, lookup=rfc):
    return cc.check(fqdn, issuer, wildcard, lookup)['allowed']


# ---- RFC 8659 4.2 / 4.3 / 4.5 の例をそのまま判定 ------------------------------
check('4.2 certs: ca1 は許可', allowed('certs.example.com', 'ca1.example.net'), True)
check('4.2 certs: ca3 は不可', allowed('certs.example.com', 'ca3.example.org'), False)
check('4.2 nocerts: 誰も不可', allowed('nocerts.example.com', 'ca1.example.net'), False)
check('4.2 malformed: 誰も不可', allowed('malformed.example.com', 'ca1.example.net'), False)
check('4.2 additive: 空+ca1 は ca1 だけ見る', allowed('mixed.example.com', 'ca1.example.net'), True)
check('4.2 account param 付きでも ca1 許可', allowed('account.example.com', 'ca1.example.net'), True)

check('4.3 wild: 通常は ca1 のみ', allowed('wild.example.com', 'ca1.example.net'), True)
check('4.3 wild: 通常で ca2 不可', allowed('wild.example.com', 'ca2.example.org'), False)
check('4.3 wild: *.wild は ca2 のみ', allowed('wild.example.com', 'ca2.example.org', True), True)
check('4.3 wild: *.wild で ca1 不可（issuewild優先）', allowed('wild.example.com', 'ca1.example.net', True), False)
check('4.3 wild2: issuewild 無し→ *.wild2 も ca1', allowed('wild2.example.com', 'ca1.example.net', True), True)
check('4.3 wild3: 通常は誰も不可（issue ";"）', allowed('wild3.example.com', 'ca2.example.org'), False)
check('4.3 wild3: *.wild3 は ca2', allowed('wild3.example.com', 'ca2.example.org', True), True)
check('4.3 wild4: issuewild だけ→通常は制限なし', allowed('wild4.example.com', 'anyone.example'), True)
check('4.3 サブドメイン sub.wild は親の RRset を使う', allowed('sub.wild.example.com', 'ca1.example.net'), True)

check('4.4 iodef は制限に関与しない', allowed('report.example.com', 'ca1.example.net'), True)
check('4.5 critical 未知タグ → ca1 も不可', allowed('new.example.com', 'ca1.example.net'), False)

check('3. 木登り: A.B.C は B.C の RRset', cc.check('a.b.c', 'example.com', False, rfc)['relevant_at'], 'b.c')
check('3. 木登り: X.Y.Z は空', cc.check('x.y.z', 'example.com', False, rfc)['relevant_at'], None)

# ---- 落とし穴1: 「CAAがある＝制限されている」ではない --------------------------
# microsoft.com / softbank.jp は contactemail しか無い。RFC 8659 3. により制限しない。
check('落とし穴1 microsoft.com は contactemail のみ→制限なし', allowed('microsoft.com', 'letsencrypt.org', False, live), True)
check('落とし穴1 softbank.jp も同じ', allowed('softbank.jp', 'letsencrypt.org', False, live), True)

# ---- 落とし穴2: パラメータの区切り。空白の有無で壊れる ----------------------------
# yahoo.co.jp は "digicert.com;cansignhttpexchanges=yes"（空白なし）
# cloudflare.com は "digicert.com; cansignhttpexchanges=yes"（空白あり）
def naive_issuer(value):
    return value.split(' ')[0]          # 素朴な実装：最初の空白まで

check('落とし穴2 素朴実装は空白なしで壊れる',
      naive_issuer('digicert.com;cansignhttpexchanges=yes') == 'digicert.com', False)
check('落とし穴2 現行は空白なしでも issuer を取れる',
      cc.parse_issue_value('digicert.com;cansignhttpexchanges=yes')[0], 'digicert.com')
check('落とし穴2 現行は空白ありでも同じ',
      cc.parse_issue_value('digicert.com; cansignhttpexchanges=yes')[0], 'digicert.com')
check('落とし穴2 yahoo.co.jp で digicert 許可', allowed('yahoo.co.jp', 'digicert.com', False, live), True)
check('落とし穴2 パラメータも取れる',
      cc.parse_issue_value('digicert.com;cansignhttpexchanges=yes')[1], {'cansignhttpexchanges': 'yes'})

# ---- 落とし穴3: wildcard は issuewild が issue を上書きする -------------------------
# okta.com: issue に letsencrypt.org はあるが、issuewild は digicert/globalsign のみ
check('落とし穴3 okta.com 通常は letsencrypt 許可', allowed('okta.com', 'letsencrypt.org', False, live), True)
check('落とし穴3 *.okta.com は letsencrypt 不可', allowed('okta.com', 'letsencrypt.org', True, live), False)
check('落とし穴3 *.okta.com は digicert 許可', allowed('okta.com', 'digicert.com', True, live), True)
# 素朴に issue と issuewild を合算すると、*.okta.com で letsencrypt が通ってしまう
recs = [cc.parse_record(r) for r in live('okta.com')[2]]
union = {cc.parse_issue_value(r['value'])[0] for r in recs if r['tag'] in ('issue', 'issuewild')}
check('落とし穴3 合算実装だと letsencrypt が混ざる', 'letsencrypt.org' in union, True)

# ---- 落とし穴4: 木登り。サブドメインは親の CAA に従う -------------------------------
# developer.okta.com は CNAME → CloudFront。CAA は空。RFC 8659 は okta.com へ登る。
r = cc.check('developer.okta.com', 'letsencrypt.org', False, live)
check('落とし穴4 developer.okta.com の Relevant は okta.com', r['relevant_at'], 'okta.com')
check('落とし穴4 登った順序', r['climbed'], ['developer.okta.com', 'okta.com'])
# www.yahoo.co.jp は CNAME → yimg.jp 配下。RFC 6844 なら CNAME 先の木も登っていた。
r = cc.check('www.yahoo.co.jp', 'globalsign.com', False, live)
check('落とし穴4 www.yahoo.co.jp は yahoo.co.jp に従う', r['relevant_at'], 'yahoo.co.jp')
check('落とし穴4 CNAME 先（yimg.jp）へは登っていない', 'yimg.jp' in ' '.join(r['climbed']), False)
# www.github.com は CNAME → github.com。リゾルバが追った結果、最初の名前で見つかる。
r = cc.check('www.github.com', 'letsencrypt.org', False, live)
check('落とし穴4 CNAME をリゾルバが追った結果は最初の名前で確定', r['relevant_at'], 'www.github.com')

# ---- 落とし穴5: タグは大文字小文字を区別しない / flags 128 --------------------------
check('落とし穴5 ISSUE も issue', cc.parse_record('0 ISSUE "ca1.example.net"')['tag'], 'issue')
check('落とし穴5 128 は critical', cc.parse_record('128 tbs "x"')['critical'], True)
check('落とし穴5 1 は critical ではない（bit 7）', cc.parse_record('1 issue "x"')['critical'], False)

print()
if fails:
    print('%d failed' % len(fails))
    raise SystemExit(1)
print('all passed')
