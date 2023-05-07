# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103379");
  script_version("2023-05-05T16:07:24+0000");
  script_tag(name:"last_modification", value:"2023-05-05 16:07:24 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2012-01-09 10:33:57 +0100 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ITRS OP5 Monitor Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ITRS OP5 Monitor
  (formerly op5 Monitor).");

  script_xref(name:"URL", value:"https://www.itrsgroup.com/products/network-monitoring-op5-monitor");
  script_xref(name:"URL", value:"https://www.op5.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default: 443);

url = "/";
buf = http_get_cache(item: url, port: port);

# <title>Welcome to op5 portal</title>
# <p><br /><img src="portal/images/header_welcome.gif" alt="Welcome to op5 Portal" /></p>
# alt="op5 Monitor: Log in" title="op5 Monitor: Log in" /></a></dt>
# <title>ITRS OP5 Monitor Portal</title>
# <h1>Welcome to the ITRS OP5 Monitor Portal</h1>
# alt="op5 Monitor: Log in" title="OP5 Monitor: Log in" />
if (concl = egrep(pattern: "(Welcome to op5 portal|op5 Monitor: Log in|ITRS OP5 Monitor Portal)", string: buf, icase: TRUE)) {

  concl = chomp(concl);
  install = url;
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  version = "unknown";

  # Version: 7.1.6  | <a href="/monitor" title="Log in">Log in</a>
  # Version: 7.5.0  | <a href="/monitor" title="Log in">Log in</a>
  vers = eregmatch(string: buf, pattern: 'Version: *([0-9.]+) *\\| *<a +href=".*/monitor"', icase: FALSE);
  if (!isnull(vers[1])) {
    version = vers[1];
    concl += '\n' + vers[0];
  }

  # nb: Newer 8.x versions are not exposing the version on the main portal page. But we can extract
  # it from here...
  if (version == "unknown") {
    url = "/about.php";
    buf = http_get_cache(item: url, port: port);

    # <p>Current OP5 Monitor System version: <strong>8.4.3
    # <p>Current OP5 Monitor System version: <strong>2019.a.2-op5.1.20190130130201.el7
    vers = eregmatch(string: buf, pattern: "Current OP5 Monitor System version:\s*(<strong>)?([0-9a-z.]+)", icase: TRUE);
    if (!isnull(vers[2])) {
      version = vers[2];
      concl += '\n' + vers[0];
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  set_kb_item(name: "op5/detected", value: TRUE);
  set_kb_item(name: "op5/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:op5:monitor:");
  if (!cpe)
    cpe = "cpe:/a:op5:monitor";

  # Only Linux based systems (RHEL, CentOS, Rocky Linux) according to:
  # https://docs.itrsgroup.com/docs/all/op5-monitor/compat-matrix-8x/index.html
  # https://docs.itrsgroup.com/docs/all/op5-monitor/compat-matrix/index.html
  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "ITRS OP5 Monitor Detection (HTTP)",
                         port: port, banner_type: "OP5 Monitor HTTP Portal Page", runs_key: "unixoide");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app:"ITRS OP5 Monitor", version: version, install: install, cpe: cpe,
                                           concludedUrl: conclUrl, concluded: concl),
              port: port);
}

exit(0);
