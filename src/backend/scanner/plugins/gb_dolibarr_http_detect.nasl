# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103143");
  script_version("2023-05-09T09:12:26+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-09 09:12:26 +0000 (Tue, 09 May 2023)");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dolibarr Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dolibarr.");

  script_xref(name:"URL", value:"http://www.dolibarr.org/");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir( make_list_unique("/", "/dolibarr", "/dolibarr/htdocs", "/htdocs", http_cgi_dirs(port: port)) ) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);

  if ("Set-Cookie: DOLSESSID" >< res && ("<title>Login" || "<title>Dolibarr") >< res &&
      ("dolibarr_logo.png" || "dolibarr.org") >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # Dolibarr 11.0.4
    vers = eregmatch(string: res, pattern: ">Dolibarr.{0,5} ([0-9.]+)<", icase: TRUE);
    if (isnull(vers[1]))
      # layout=classic&amp;version=16.0.4">
      vers = eregmatch(pattern: "layout=[^&]+&amp;version=([0-9.]+)", string: res);

    if (!isnull(vers[1]))
       version = vers[1];

    set_kb_item(name: "dolibarr/detected", value: TRUE);
    set_kb_item(name: "dolibarr/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dolibarr:dolibarr:");
    if (!cpe)
      cpe = "cpe:/a:dolibarr:dolibarr";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Dolibarr ERP/CRM", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
