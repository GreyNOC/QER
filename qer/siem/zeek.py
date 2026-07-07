"""Zeek detection script.

Unlike the other exporters (which alert on QER's findings feed), this emits a
Zeek policy script that flags quantum-vulnerable and weak TLS **on the wire, in
real time** — no QER scan required. It keys off the negotiated version, cipher,
and key-exchange group that Zeek's SSL analyzer already records, so it doubles
as a continuous hybrid-downgrade sensor when ``notice_classical_kex`` is enabled.
"""

from __future__ import annotations

from typing import Optional

from ..models import EndpointReport

_ZEEK_SCRIPT = """\
##! QER - Quantum Exposure Radar
##! Passive TLS cryptographic-risk notices for Zeek.
##! Load with:  zeek -i <iface> /path/to/qer-quantum-radar.zeek
##! or add to local.zeek:  @load /path/to/qer-quantum-radar.zeek

@load base/protocols/ssl
@load base/frameworks/notice

module QER;

export {
    redef enum Notice::Type += {
        ## TLS 1.1 or below (RFC 8996) / SSLv3 negotiated.
        Weak_TLS_Version,
        ## RSA key transport or static key exchange: no forward secrecy, HNDL-exposed.
        No_Forward_Secrecy,
        ## RC4 / 3DES / single-DES / NULL / MD5 cipher in use.
        Broken_Cipher,
        ## Classical (ECDHE/DHE) key exchange with no PQ protection. Noisy; off by default.
        Classical_KeyExchange,
    };

    ## Emit a per-connection notice for every classical key exchange. This fires
    ## on essentially all of today's TLS, so it is disabled by default; enable it
    ## to use Zeek as a continuous hybrid-downgrade sensor.
    const notice_classical_kex: bool = F &redef;

    const weak_versions: set[string] = {
        "SSLv2", "SSLv3", "TLSv10", "TLSv11",
    } &redef;

    ## Post-quantum / hybrid key-exchange groups Zeek may report in $curve.
    ## Older Zeek builds without the PQ group-name table log these by raw
    ## codepoint as "unknown-NNNN", so both spellings are recognised.
    const pq_groups: set[string] = {
        "X25519MLKEM768", "X25519Kyber768Draft00",
        "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "SecP256r1Kyber768Draft00",
        "unknown-4588", "unknown-25497", "unknown-4587", "unknown-4589", "unknown-25498",
    } &redef;
}

redef record SSL::Info += {
    ## QER: whether the negotiated key-exchange group is post-quantum/hybrid.
    ## Adds a `qer_pq` column to ssl.log so `qer passive` can read it directly.
    qer_pq: bool &log &optional;
};

function cipher_is_broken(cipher: string): bool {
    return /RC4|3DES|DES_CBC|_DES_|WITH_NULL|_MD5/ in cipher;
}

function cipher_has_fs(cipher: string): bool {
    # TLS 1.3 suites (TLS_AES_*/TLS_CHACHA20_*) carry no (EC)DHE token but are
    # always ephemeral and forward-secret, so match them explicitly to avoid a
    # No_Forward_Secrecy notice on every TLS 1.3 connection.
    return /ECDHE|DHE/ in cipher || /^TLS_AES_|^TLS_CHACHA20_/ in cipher;
}

event ssl_established(c: connection) {
    if ( ! c?$ssl )
        return;

    local info = c$ssl;
    local ver = info?$version ? info$version : "";
    local cipher = info?$cipher ? info$cipher : "";
    local grp = info?$curve ? info$curve : "";

    if ( grp != "" )
        c$ssl$qer_pq = (grp in pq_groups);

    if ( ver in weak_versions )
        NOTICE([$note=Weak_TLS_Version, $conn=c,
                $msg=fmt("QER: weak TLS version %s negotiated (cipher %s)", ver, cipher)]);

    if ( cipher != "" && cipher_is_broken(cipher) )
        NOTICE([$note=Broken_Cipher, $conn=c,
                $msg=fmt("QER: broken/deprecated cipher %s", cipher)]);

    if ( cipher != "" && ! cipher_has_fs(cipher) )
        NOTICE([$note=No_Forward_Secrecy, $conn=c,
                $msg=fmt("QER: no forward secrecy (cipher %s) - recorded traffic is HNDL-exposed", cipher)]);

    if ( notice_classical_kex && grp != "" && grp !in pq_groups )
        NOTICE([$note=Classical_KeyExchange, $conn=c,
                $msg=fmt("QER: classical key-exchange group '%s' (no post-quantum protection)", grp)]);
}
"""


def to_zeek(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    return _ZEEK_SCRIPT
