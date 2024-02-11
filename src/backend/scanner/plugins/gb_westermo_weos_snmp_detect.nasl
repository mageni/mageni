# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106196");
  script_version("2024-02-07T14:36:41+0000");
  script_tag(name:"last_modification", value:"2024-02-07 14:36:41 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-08-24 11:10:05 +0700 (Wed, 24 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Westermo WeOS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Westermo WeOS devices.");

  script_xref(name:"URL", value:"https://www.westermo.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# Westermo Falcon, primary: v4.32.5, backup: v4.32.5, bootloader: v2017.12.0-6
# Westermo Lynx, primary: v4.12.1, backup: v4.12.1, bootloader: v4.11
if (egrep(string: sysdesc, pattern: "^Westermo.*, primary:.*, backup:.*, bootloader:")) {
  model = "unknown";
  version = "unknown";
  location = "/";
  concluded = "  SNMP OID(s):" + '\n    1.3.6.1.2.1.1.1.0 (sysDescr): ' + sysdesc;

  mo = eregmatch(pattern: "Westermo (.*), primary:", string: sysdesc);
  if (!isnull(mo[1])) {
    model = mo[1];

    mod_oid = "1.3.6.1.2.1.47.1.1.1.1.13.3";
    mod = snmp_get(port: port, oid: mod_oid);
    if (!mod || mod == "") {
      mod_oid = "1.3.6.1.2.1.47.1.1.1.1.13.4";
      mod = snmp_get(port: port, oid: mod_oid);
    }

    if (mod && mod != "") {
      model += " " + mod;
      concluded += '\n    ' + mod_oid + " (Model): " + mod;
      set_kb_item(name: "westermo/weos/model", value: model);
    }
  }

  vers = eregmatch(pattern: "primary: v([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "westermo/weos/detected", value: TRUE);
  set_kb_item(name: "westermo/weos/snmp/detected", value: TRUE);

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:westermo:weos:");
  if (!os_cpe)
    os_cpe = "cpe:/o:westermo:weos";

  os_name = "Westermo WeOS";

  if (model != "unknown") {
    hw_name = "Westermo " + model;
    cpe_mod = tolower(str_replace(string: model, find: " ", replace: "_"));
    hw_cpe = "cpe:/h:westermo:" + cpe_mod;
  } else {
    hw_name = "Westermo Unknown Model";
    hw_cpe = "cpe:/h:westermo:device";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, banner_type: "SNMP sysDescr", port: port,
                         proto: "udp", banner: sysdesc, desc: "Westermo WeOS Detection (SNMP)",
                         runs_key: "unixoide");

  register_product(cpe: os_cpe, location: location, port: port, proto: "udp", service: "snmp");
  register_product(cpe: hw_cpe, location: location, port: port, proto: "udp", service: "snmp");

  report  = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                   concluded: concluded);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

  log_message(port: port, data: report, proto: "udp");

  exit(0);
}

exit(0);
