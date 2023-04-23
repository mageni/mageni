# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803794");
  script_version("2023-04-05T10:10:37+0000");
  script_tag(name:"last_modification", value:"2023-04-05 10:10:37 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2014-01-21 13:04:26 +0530 (Tue, 21 Jan 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Open Web Analytics (OWA) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Open Web Analytics (OWA).");

  script_xref(name:"URL", value:"https://www.openwebanalytics.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/owa", "/analytics", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php?owa_do=base.loginForm";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # nb: This was the same for 1.5.7 and 1.7.5:
  # <title>Login - Open Web Analytics</title>
  #
  # nb: The one without the version was from 1.7.5:
  # <a href="http://www.openwebanalytics.com">Web Analytics</a> powered by <a href="http://www.openwebanalytics.com">Open Web Analytics</a> - v: 1.5.7</span>
  # <a href="http://www.openwebanalytics.com">Web Analytics</a> powered by <a href="http://www.openwebanalytics.com">Open Web Analytics</a>.</span>
  if ("Open Web Analytics</" >< res && "OWA.config.main_url" >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # owa.css?version=1.6.2
    # owa.js?version=1.6.2
    vers = eregmatch(pattern: "\.(js|css)\?version=([0-9.]+)", string: res);
    if (!isnull(vers[2]))
      version = vers[2];

    set_kb_item(name: "open_web_analytics/detected", value: TRUE);
    set_kb_item(name: "open_web_analytics/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openwebanalytics:open_web_analytics:");
    if (!cpe)
      cpe = "cpe:/a:openwebanalytics:open_web_analytics";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Open Web Analytics (OWA)", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
