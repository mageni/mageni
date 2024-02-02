# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800681");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("2532|Gigs Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of 2532-Gigs.");
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

foreach dir (make_list_unique("/2532Gigs", "/Gigs", "/bands", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache(port: port, item: url);

  if ("Powered by 2532|Gigs" >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    vers = eregmatch(pattern: "2532\|Gigs v([0-9]+\.[0-9]\.[0-9])", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "2532_gigs/detected", value: TRUE);
    set_kb_item(name: "2532_gigs/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:2532gigs:2532gigs:");
    if (!cpe)
      cpe = "cpe:/a:2532gigs:2532gigs";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "2532Gigs", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
