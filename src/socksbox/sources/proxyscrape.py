"""ProxyScrape JSON source adapter for SocksBox."""

from __future__ import annotations

from socksbox.parser import load_proxyscrape_json
from socksbox.sources.base import LoadResult


class ProxyscrapeSource:
    """Load and parse proxies from the ProxyScrape JSON API.

    This adapter wraps :func:`socksbox.parser.load_proxyscrape_json` and
    self-labels every diagnostic record with the source URL.
    """

    url: str = (
        "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies"
        "&proxy_format=protocolipport&format=json&protocol=socks5%2Csocks4&anonymity=elite"
        "&country=af%2Cal%2Cdz%2Cad%2Cao%2Car%2Cam%2Cau%2Cat%2Caz%2Cbd%2Cby%2Cbe%2Cbj"
        "%2Cbm%2Cbt%2Cbo%2Cbw%2Cbg%2Cbf%2Cbi%2Ckh%2Ccm%2Cca%2Ctd%2Ccl%2Ccn%2Cco%2Ccg"
        "%2Ccr%2Chr%2Ccy%2Ccz%2Cdk%2Cdo%2Cec%2Ceg%2Csv%2Cgq%2Cee%2Csz%2Ct%2Cfj%2Cfi"
        "%2Cfr%2Cgm%2Cge%2Cde%2Cgh%2Cgi%2Cgr%2Cgu%2Cgt%2Cgn%2Cht%2Chn%2Chk%2Chu%2Cin"
        "%2Cid%2Cir%2Ciq%2Cie%2Cil%2Cit%2Cjm%2Cjp%2Cjo%2Ckz%2Cke%2Ckr%2Ckg%2Clv%2Clb"
        "%2Cls%2Clt%2Cmg%2Cmw%2Cmy%2Cmv%2Cml%2Cmt%2Cmu%2Cmx%2Cmd%2Cmn%2Cme%2Cma%2Cmz"
        "%2Cmm%2Cna%2Cnp%2Cnl%2Cnz%2Cni%2Cng%2Cmk%2Cno%2Cpk%2Cps%2Cpa%2Cpy%2Cpe%2Cph"
        "%2Cpl%2Cpt%2Cpr%2Cqa%2Cro%2Crw%2Ckn%2Csa%2Csn%2Crs%2Csc%2Csl%2Csg%2Csk%2Csi"
        "%2Cso%2Cza%2Ces%2Clk%2Csd%2Cse%2Cch%2Csy%2Ctw%2Ctj%2Ctz%2Cth%2Ctl%2Ctg%2Ctn"
        "%2Ctr%2Cug%2Cua%2Cae%2Cgb%2Cus%2Cuy%2Cuz%2Cve%2Cvn%2Cvi%2Cye%2Czw"
    )
    prints_summary: bool = False

    def load(self, verify_ssl: bool = True) -> LoadResult:
        """Fetch and parse ProxyScrape JSON.

        Args:
            verify_ssl: Whether to verify TLS certificates when fetching data.

        Returns:
            A :class:`~socksbox.sources.base.LoadResult` containing the parsed
            proxies and diagnostic records.
        """
        proxies, records = load_proxyscrape_json(verify_ssl=verify_ssl)
        labelled_records = []
        for record in records:
            enriched = dict(record)
            enriched.setdefault("source", self.url)
            labelled_records.append(enriched)
        return LoadResult(proxies=proxies, records=labelled_records)


DEFAULT_PROXYSCRAPE_SOURCE = ProxyscrapeSource()
