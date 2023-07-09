# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113588");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2019-11-26 16:51:55 +0200 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Caucho Resin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Caucho Resin.");

  script_xref(name:"URL", value:"https://caucho.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/";
install = url;

res = http_get_cache(port: port, item: url, fetch404: TRUE);

# <head><title>Resin&#174; Default Home Page</title></head>
# <h1 style="background: #ccddff">Resin&#174; Default Home Page</h1>
if (res !~ "Server\s*:\s*Resin" && res !~ "<(title|h1[^>]*)>Resin.+Default Home Page</(title|h1)>") {
  url = "/resin-doc/";
  res = http_get_cache(port: port, item: url, fetch404: TRUE);

  # On 404 pages:
  # <small>
  # Resin/4.0.48
  # Server: '<redacted>'
  # </small>
  #
  # On "/resin-doc/":
  # <td width="70%"><h1>Resin Documentation<td width="20%">
  #
  # nb: "eregmatch()" instead of "!~" for the "Resin.*Server:" pattern is used here because the
  # latter had caused false detections for systems which had responded with something like e.g. the
  # following (due to "!~" being case insensitive):
  # HTTP/1.1 501 no such file '/resin-doc/'
  # Server: pve-api-daemon/3.0
  #
  if (">Resin Documentation<" >!< res && !eregmatch(string: res, pattern:"Resin[^S]+Server:.+", icase: FALSE)) {
    url = "/resin-admin";
    res = http_get_cache(port: port, item: url, fetch404: TRUE);
    if (!eregmatch(string: res, pattern:"Resin[^S]+Server:.+", icase: FALSE) && "<title>Resin Admin Login" >!< res) {
      url = "/caucho-status";
      res = http_get_cache(port: port, item: url);
      # nb: See pre2008/resin_server_status.nasl (which is using the same pattern) for examples
      if (!egrep(string: res, pattern: "<(title|h1)>Status : Caucho Servlet Engine", icase: FALSE) ||
          res !~ "(%cpu/thread|Resin)")
        exit(0);
    }
  }
}

version = "unknown";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "caucho/resin/detected", value: TRUE);
set_kb_item(name: "caucho/resin/http/detected", value: TRUE);

# Server: Resin/4.0.18
vers = eregmatch(pattern: "Server\s*:\s*Resin/([0-9.]+)", string: res, icase: TRUE);
if (isnull(vers[1])) {
  url = "/resin-doc/changes/changes.xtp";
  res = http_get_cache(port: port, item: url);
  # <h2>4.0.64 - in progress</h2>
  vers = eregmatch(pattern: ">Resin Change Log</h1></div>[^/]+/a><h2>([0-9.]+)", string: res);
  if (isnull(vers[1])) {
    url = "/resin-admin/";
    res = http_get_cache(port: port, item: url);
    # <em>Resin-4.0.66 (built Mon, 29 Nov 2021 04:22:10 PST)</em>
    vers = eregmatch(pattern: "<em>Resin\-([0-9.]+)", string: res);
    if (isnull(vers[1])) {
      # Resin/4.0.53
      vers = eregmatch(pattern: "Resin/([0-9.]+)", string: res);
      if (isnull(vers[1])) {
        url = "/caucho-status";
        res = http_get_cache(port: port, item: url);
        # <hr><em>Resin/3.1.10<em></body></html>
        vers = eregmatch(pattern: ">Resin/([0-9.]+)", string: res);
      }
    }
  }
}

if (!isnull(vers[1])) {
  version = vers[1];
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:caucho:resin:");
if (!cpe)
  cpe = "cpe:/a:caucho:resin";

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "Caucho Resin", version: version, install: install, cpe: cpe,
                                         concluded: vers[0], concludedUrl: conclUrl),
            port: port);

exit(0);
