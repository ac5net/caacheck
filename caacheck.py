#!/usr/bin/env python3
"""caacheck.py - CAA (RFC 8659) の Relevant RRset を求め、発行可否を判定する

使い方:
    ./caacheck.py <FQDN> <issuer-domain-name> [--wildcard]
    例: ./caacheck.py developer.okta.com letsencrypt.org
        ./caacheck.py okta.com letsencrypt.org --wildcard

DNSは DoH（dns.google）で引く。--fixtures <json> を渡すと
ネットワークに出ず、JSONに書いた応答で動く（テスト用）。
"""
import sys, json, re, urllib.request

TIMEOUT = 10
UA = 'caacheck/1.0'
RESTRICTIVE_TAGS = ('issue', 'issuewild')   # RFC 8659 3.: これ以外だけなら発行を制限しない


# ----------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------
def doh_caa(name):
    """dns.google に CAA を問い合わせる。戻り値は (status, ad, [presentation形式の文字列])

    DoH の CAA 応答の data は '0 issue "pki.goog"' のような表示形式で返る。
    Answer が無い応答（NXDOMAIN / NOERROR-NODATA）では 'Answer' キー自体が無い。
    CNAME は dns.google が追ってくれる（RFC 8659 3. の「エイリアスは追う」に相当）。
    """
    url = 'https://dns.google/resolve?name=%s&type=CAA' % name
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        j = json.load(r)
    caa = [a.get('data', '') for a in j.get('Answer', []) if a.get('type') == 257]
    return j.get('Status'), bool(j.get('AD')), caa


def make_fixture_lookup(path):
    """fixtures JSON: {"name": {"Status":0,"AD":false,"caa":["0 issue \"x\""]}, ...}
    無い名前は NOERROR-NODATA 扱い（空）。"""
    with open(path, encoding='utf-8') as f:
        table = json.load(f)

    def lookup(name):
        e = table.get(name.rstrip('.').lower())
        if not e:
            return 0, False, []
        return e.get('Status', 0), bool(e.get('AD')), list(e.get('caa', []))
    return lookup


# ----------------------------------------------------------------------
# パース
# ----------------------------------------------------------------------
_PRES = re.compile(r'^\s*(\d{1,3})\s+([A-Za-z0-9-]+)\s+"?(.*?)"?\s*$')


def parse_record(pres):
    """'0 issue "pki.goog"' → {'flags':0,'tag':'issue','value':'pki.goog','critical':False}

    RFC 8659 4.1: タグの照合は大文字小文字を区別しない → 小文字に正規化する。
    Flags の bit 0（MSB）が critical。表示形式では 128 がそれに当たる。
    """
    m = _PRES.match(pres)
    if not m:
        raise ValueError('CAA presentation format ではない: %r' % pres)
    flags = int(m.group(1))
    return {'flags': flags, 'tag': m.group(2).lower(), 'value': m.group(3),
            'critical': bool(flags & 0x80)}


_LABEL = r'[A-Za-z0-9](?:-*[A-Za-z0-9])*'
_ISSUER = re.compile(r'^\s*(%s(?:\.%s)*)?\s*(?:;(.*))?$' % (_LABEL, _LABEL))


def parse_issue_value(value):
    """issue / issuewild の値を (issuer_domain_name or None, {param: value}) にする

    RFC 8659 4.2 ABNF:
      issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]]
    ・"digicert.com; account=1"  も  "digicert.com;cansignhttpexchanges=yes" も合法
      → 空白の有無に依存してはいけない。';' で切ってから strip する
    ・issuer-domain-name が空（";" だけ）→ 発行禁止の意思表示
    ・文法に合わない値 → 空の issuer-domain-name と同じに扱う MUST（= 禁止）
    """
    m = _ISSUER.match(value)
    if not m:
        return None, {}          # malformed → 空扱い（禁止）
    issuer = (m.group(1) or '').strip().lower() or None
    params = {}
    rest = m.group(2) or ''
    for p in rest.split(';'):
        p = p.strip()
        if not p:
            continue
        if '=' not in p:
            return None, {}      # parameter は tag=value 必須。崩れていたら malformed
        k, v = p.split('=', 1)
        params[k.strip().lower()] = v.strip()
    return issuer, params


# ----------------------------------------------------------------------
# RFC 8659 3. Relevant RRset
# ----------------------------------------------------------------------
def relevant_rrset(fqdn, lookup=doh_caa):
    """ルート直前まで親へ登り、最初に見つかった空でない CAA RRset を返す。

    CNAME/DNAME の追跡は再帰リゾルバの仕事（RFC 8659 3. および 7.）。
    RFC 6844 のように CNAME の先の木まで自分で登ってはいけない。
    戻り値: (見つかった名前 or None, [record dict], climbed_names, ad)
    """
    name = fqdn.rstrip('.').lower()
    climbed = []
    while name and name != '.':
        climbed.append(name)
        status, ad, recs = lookup(name)
        if status not in (0, 3):
            # SERVFAIL 等。RFC 8659 6.3 は CA が「発行不可」と解釈してよい（MAY）としている
            raise RuntimeError('DNS status %s for %s' % (status, name))
        if recs:
            return name, [parse_record(r) for r in recs], climbed, ad
        if '.' not in name:
            break
        name = name.split('.', 1)[1]
    return None, [], climbed, False


# ----------------------------------------------------------------------
# 判定
# ----------------------------------------------------------------------
def evaluate(rrset, issuer_domain, wildcard=False):
    """Relevant RRset に対して、issuer_domain が発行できるかを判定する。

    戻り値: (allowed: bool, reason: str)
    """
    issuer_domain = issuer_domain.lower().rstrip('.')

    # 4.5 critical フラグ付きの未知タグがあれば、誰も発行できない
    for r in rrset:
        if r['critical'] and r['tag'] not in ('issue', 'issuewild', 'iodef'):
            return False, 'critical な未知タグ %r があるため発行不可（RFC 8659 4.5）' % r['tag']

    # 3. 制限するタグが無ければ CAA は発行を制限しない
    restrictive = [r for r in rrset if r['tag'] in RESTRICTIVE_TAGS]
    if not restrictive:
        others = sorted({r['tag'] for r in rrset})
        return True, 'issue/issuewild が無い（%s のみ）ため CAA は発行を制限しない（RFC 8659 3.）' % (
            ','.join(others) if others else 'なし')

    # 4.3 wildcard 要求で issuewild が1つでもあれば issue は全て無視
    if wildcard:
        wilds = [r for r in rrset if r['tag'] == 'issuewild']
        effective = wilds if wilds else [r for r in rrset if r['tag'] == 'issue']
        basis = 'issuewild' if wilds else 'issue（issuewild が無いので流用）'
    else:
        effective = [r for r in rrset if r['tag'] == 'issue']   # issuewild は非wildcardでは無視
        basis = 'issue'

    if not effective:
        # 例: issuewild だけあって issue が無い場合の非wildcard要求 → 制限なし
        return True, '%s 要求に適用されるタグが無いため制限しない' % ('wildcard' if wildcard else '通常')

    allowed_names = set()
    forbid_only = True
    for r in effective:
        issuer, params = parse_issue_value(r['value'])
        if issuer:
            allowed_names.add(issuer)
            forbid_only = False
    # 4.2 additive: 空の issuer と非空の issuer が混在すれば非空だけを見ればよい
    if forbid_only:
        return False, '%s の値がすべて空または不正のため、どの CA も発行できない（RFC 8659 4.2）' % basis
    if issuer_domain in allowed_names:
        return True, '%s に %s が含まれる' % (basis, issuer_domain)
    return False, '%s に %s が無い（許可: %s）' % (basis, issuer_domain, ', '.join(sorted(allowed_names)))


def check(fqdn, issuer_domain, wildcard=False, lookup=doh_caa):
    found_at, rrset, climbed, ad = relevant_rrset(fqdn, lookup)
    allowed, reason = evaluate(rrset, issuer_domain, wildcard)
    return {'fqdn': fqdn, 'wildcard': wildcard, 'issuer': issuer_domain,
            'relevant_at': found_at, 'climbed': climbed, 'dnssec_ad': ad,
            'rrset': rrset, 'allowed': allowed, 'reason': reason}


def main(argv):
    args = [a for a in argv if not a.startswith('--')]
    if len(args) < 2:
        print(__doc__)
        return 2
    wildcard = '--wildcard' in argv
    lookup = doh_caa
    if '--fixtures' in argv:
        lookup = make_fixture_lookup(argv[argv.index('--fixtures') + 1])
    res = check(args[0], args[1], wildcard, lookup)
    print('対象        : %s%s' % ('*.' if wildcard else '', res['fqdn']))
    print('登った名前  : %s' % ' → '.join(res['climbed']))
    print('Relevant    : %s' % (res['relevant_at'] or '（なし）'))
    print('DNSSEC(AD)  : %s' % ('yes' if res['dnssec_ad'] else 'no'))
    for r in res['rrset']:
        print('  %3d %-12s %s' % (r['flags'], r['tag'], r['value']))
    print('判定        : %s  %s' % ('許可' if res['allowed'] else '不可', res['reason']))
    return 0 if res['allowed'] else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
