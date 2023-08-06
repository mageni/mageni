# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105244");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-07 13:29:41 +0200 (Tue, 07 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ArubaOS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of ArubaOS.");

  script_xref(name:"URL", value:"https://www.arubanetworks.com/products/network-management-operations/arubaos/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit( 0 );

# ArubaOS (MODEL: Aruba3400), Version 6.3.1.1 (40563)
# ArubaOS (MODEL: Aruba200-US), Version 5.0.4.16 (43995)
# ArubaOS Version 6.1.2.3-2.1.0.0
# ArubaOS (MODEL: Aruba7005), Version 8.5.0.0-2.1.0.3 (77821)
# ArubaOS (MODEL: 304), Version 8.9.0.2-8.9.0.2
if ("ArubaOS" >!< sysdesc)
  exit(0);

set_kb_item(name: "aruba/arubaos/detected", value: TRUE);
set_kb_item(name: "aruba/arubaos/snmp/detected", value: TRUE);

cpe = "cpe:/o:arubanetworks:arubaos";

version = "unknown";
model = "unknown";
location = "/";
os_name = "ArubaOS";

vers = eregmatch(pattern: "Version ([0-9.-]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

b = eregmatch(pattern: "Version [^ ]+ \(([0-9]+)\)", string: sysdesc);
if (!isnull(b[1])) {
  build = b[1];
  set_kb_item(name: "aruba/arubaos/build", value: build);
}

mod = eregmatch(pattern: "\(MODEL: (Aruba)?([0-9]+)", string: sysdesc);
if (!isnull(mod[2])) {
  model = mod[2];
  set_kb_item(name: "aruba/arubaos/model", value: model);
}

os_cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/o:arubanetworks:arubaos:");
if (!os_cpe)
  os_cpe = "cpe:/o:arubanetworks:arubaos";

os_register_and_report(os: os_name, cpe: os_cpe, banner_type: "SNMP sysDescr OID" , port: port, proto: "udp",
                       banner: sysdesc, runs_key: "unixoide", desc: "ArubaOS Detection (SNMP)");

if (model != "unknown") {
  hw_name = "Aruba " + model;
  hw_cpe = "cpe:/h:arubanetworks:" + model;
} else {
  hw_name = "Aruba Unknown Model";
  hw_cpe = "cpe:/h:arubanetworks:unknown_model";
}

register_product(cpe: os_cpe, location: location, port: port, proto: "udp", service: "snmp");
register_product(cpe: hw_cpe, location: location, port: port, proto: "udp", service: "snmp");

report  = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                 concluded: sysdesc);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

log_message(port: port, data: report, proto: "udp");

exit(0);
