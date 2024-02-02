# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140815");
  script_version("2023-12-08T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-12-08 05:05:53 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-02-27 12:00:27 +0700 (Tue, 27 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM Security Guardium Big Data Intelligence Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of IBM Security Guardium Big Data Intelligence.");

  script_xref(name:"URL", value:"https://www.ibm.com/us-en/marketplace/guardium-big-data-intelligence");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8443);

res = http_get_cache(port: port, item: "/");

if ("IBM Security - Login - Guardium Big Data Intelligence - Login" >< res && "login.xhtml" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "<span>v([0-9.]+)</span>", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "ibm/guardium/big_data_intelligence/detected", value: TRUE);
  set_kb_item(name: "ibm/guardium/big_data_intelligence/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:security_guardium_big_data_intelligence:");
  if (!cpe)
    cpe = 'cpe:/a:ibm:security_guardium_big_data_intelligence';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "IBM Security Guardium Big Data Intelligence", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
