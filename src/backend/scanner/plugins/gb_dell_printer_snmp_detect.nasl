# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151378");
  script_version("2023-12-14T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-12-14 05:05:32 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-12 07:17:30 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell Printer Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Dell printer devices.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# Dell 5130cdn Color Laser; Net 15.16, Controller 201009021658, Engine 04.67.00
# Dell Color Laser 3110cn; Net 8.43, Controller 200707111148, Engine 05.09.00
# Dell B2360dn Laser Printer version NH.CY.N439 kernel 3.0.0 All-N-1
# Dell 1135n Laser MFP; 2.70.00.89      04-28-2011;Engine 1.02.45;NIC V4.01.00;S/N 2CWSTQ1
# Dell MFP H815dw; Controller 201610240647, Engine 00.20.00
if (sysdesc !~ "^Dell .*(Laser|Printer|MFP)")
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name: "dell/printer/detected", value: TRUE);
set_kb_item(name: "dell/printer/snmp/detected", value: TRUE);
set_kb_item(name: "dell/printer/snmp/port", value: port);
set_kb_item(name: "dell/printer/snmp/" + port + "/banner", value: sysdesc);

mod = eregmatch(pattern: "^Dell (.*)(Laser Printer)", string: sysdesc);
if (isnull(mod[2]))
  mod = eregmatch(pattern: "^Dell ([^;]+)", string: sysdesc);

if (!isnull(mod[1])) {
  model = mod[1];
  model = str_replace(string: model, find: " Printer", replace: "");
  model = str_replace(string: model, find: "  ", replace: " ");
  model = chomp(model);
} else {
  mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
  m = snmp_get(port: port, oid: mod_oid);
  mod = eregmatch(pattern: "^Dell ([^;]+)", string: m);
  if (!isnull(mod[1])) {
    model = mod[1];
    model = str_replace(string: model, find: " Printer", replace: "");
    model = str_replace(string: model, find: "  ", replace: " ");
    model = chomp(model);
    set_kb_item(name: "dell/printer/snmp/" + port + "/concludedMod", value: m);
    set_kb_item(name: "dell/printer/snmp/" + port + "/concludedModOID", value: mod_oid);
  }
}

vers = eregmatch(pattern: "Controller ([0-9]+)", string: sysdesc);
if (isnull(vers[1]))
  vers = eregmatch(pattern: "version ([^ ]+)", string: sysdesc);

if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "dell/printer/snmp/" + port + "/model", value: model);
set_kb_item(name: "dell/printer/snmp/" + port + "/version", value: version);

exit(0);
