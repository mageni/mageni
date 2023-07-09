# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100196");
  script_version("2023-06-29T08:15:14+0000");
  script_tag(name:"last_modification", value:"2023-06-29 08:15:14 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("A-A-S Application Access Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 6262);
  script_mandatory_keys("AAS/banner");

  script_tag(name:"summary", value:"HTTP based detection of A-A-S Application Access Server.");

  script_xref(name:"URL", value:"http://www.klinzmann.name/a-a-s/index_en.html");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 6262);

if(!banner = http_get_remote_headers(port: port))
  exit(0);

if(egrep(pattern: "^[Ss]erver\s*:\s*AAS", string: banner, icase: FALSE)) {
  vers = "unknown";
  install = "/";

  version = eregmatch(string: banner, pattern: "^[Ss]erver\s*:\s*AAS/([0-9.]+)", icase: FALSE);
  if(!isnull(version[1]))
    vers = version[1];

  set_kb_item(name: "aas/detected", value: TRUE);
  set_kb_item(name: "aas/http/detected", value: TRUE);

  cpe = build_cpe(value: vers, exp:"^([0-9.]+)", base: "cpe:/a:klinzmann:application_access_server:");
  if(!cpe)
    cpe = "cpe:/a:klinzmann:application_access_server";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "A-A-S Application Access Server", version: vers, install: install,
                                           cpe: cpe, concluded: version[1]),
              port: port);
}

exit(0);
