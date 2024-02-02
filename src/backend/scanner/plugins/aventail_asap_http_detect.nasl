# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17583");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-01-30T14:37:03+0000");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Aventail ASAP Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Aventail SSL VPN appliance.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8443);

url = "/console/login.do";

res = http_get_cache(port: port, item: url);

if ("<title>ASAP Management Console Login</title>" >< res) {
  version = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "aventail/asap/detected", value: TRUE);
  set_kb_item(name: "aventail/asap/http/detected", value: TRUE);

  cpe = "cpe:/a:aventail:asap";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Aventail ASAP", version: version, install: "/", cpe: cpe,
                                           concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
