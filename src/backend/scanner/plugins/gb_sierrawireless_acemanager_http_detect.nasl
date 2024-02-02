# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106075");
  script_version("2024-01-16T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-01-16 05:05:27 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-05-17 08:27:15 +0700 (Tue, 17 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_name("Sierra Wireless AceManager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection Sierra Wireless AceManager.");

  script_xref(name:"URL", value:"https://www.sierrawireless.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 9443);

res = http_get_cache(item: "/", port: port);

if ("<title>::: ACEmanager :::</title>" >< res && "Sierra Wireless, Inc." >< res) {
  version = "unknown";
  install = "/";

  set_kb_item(name: "sierra_wireless/acemanager/detected", value: TRUE);
  set_kb_item(name: "sierra_wireless/acemanager/http/detected", value: TRUE);

  cpe = "cpe:/a:sierra_wireless:acemanager";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  # > ALEOS Version 4.15.3
  os_vers = eregmatch(pattern: ">\s*ALEOS Version ([0-9.]+)", string: res);
  if (!isnull(os_vers[1]))
    os_version = os_vers[1];

  os_cpe = build_cpe(value: os_vers[1], exp: "^([0-9.]+)", base: "cpe:/o:sierrawireless:aleos:");
  if (!os_cpe)
    os_cpe = "cpe:/o:sierrawireless:aleos";

  os_register_and_report(os: "Sierra Wireless ALEOS", version: os_version, cpe: os_cpe, port: port,
                         desc: "Sierra Wireless AceManager Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: os_cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Sierra Wireless AceManager", version: version,
                                           install: install, cpe: cpe),
              port: port);
}

exit(0);
