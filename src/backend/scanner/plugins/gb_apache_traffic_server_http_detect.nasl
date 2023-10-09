# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100796");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-09-10 15:25:30 +0200 (Fri, 10 Sep 2010)");
  script_name("Apache Traffic Server (ATS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl", "proxy_use.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128, "Services/www", 80, 443);
  script_mandatory_keys("ATS/banner");

  script_xref(name:"URL", value:"https://trafficserver.apache.org/");

  script_tag(name:"summary", value:"HTTP based detection of Apache Traffic Server (ATS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

ports = make_list();
proxy_ports = service_get_ports(default_port_list: make_list(8080, 3128), proto: "http_proxy");
if (proxy_ports)
  ports = make_list(ports, proxy_ports);

www_ports = http_get_ports(default_port_list: make_list(80, 443));
if (www_ports)
  ports = make_list(ports, www_ports);

foreach port (ports) {

  banner = http_get_remote_headers(port: port);

  # Server: ATS
  # Server: ATS/6.0.0
  # Server: ATS/8.0.2
  # Server: ATS/9.1.10.57
  # Via: http/1.1 $hostname (ApacheTrafficServer)
  # Via: http/1.1 $hostname (ApacheTrafficServer/6.2.1 [c s f ])
  # Via: http/1.1 traffic_server (ApacheTrafficServer/9.0.1 [c s f ])
  if (!banner || !concl = egrep(string: banner, pattern: '^([Ss]erver\\s*:\\s*ATS(/|[\r\n]*$)|[Vv]ia\\s*:.*ApacheTrafficServer)', icase: FALSE))
    continue;

  concluded = chomp(concl);

  install = "/";
  version = "unknown";

  vers = eregmatch(pattern: "(Server\s*:\s*ATS|ApacheTrafficServer)/([0-9.]+)", string: banner);
  if (!isnull(vers[2]))
    version = vers[2];

  set_kb_item(name: "apache/ats/detected", value: TRUE);
  set_kb_item(name: "apache/ats/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp:"^([0-9.]+)", base: "cpe:/a:apache:traffic_server:");
  if(!cpe)
    cpe = "cpe:/a:apache:traffic_server";

  register_product(cpe: cpe, location: install, port: port, service: "http_proxy");
  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache Traffic Server (ATS)", version: version, install: install,
                                           cpe: cpe, concluded: concluded),
              port: port);
}

exit(0);
