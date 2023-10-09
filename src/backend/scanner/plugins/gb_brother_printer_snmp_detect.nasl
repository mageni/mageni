# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170549");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-22 14:43:18 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brother Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Brother printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

function extract_fw_version(oid, port) {
  local_var oid, port, vers, ver;

  vers = snmp_get(port: port, oid: oid);
  # FIRMVER=\"J1307260917:0F90\"
  # FIRMVER=\"1.35\"
  ver = eregmatch(pattern: 'FIRMVER=[\\]"([A-Z]{1,2})', string: vers);

  if (!isnull(ver[1])) {
    set_kb_item(name: "brother/printer/snmp/" + port + "/concludedFwOID", value: oid);
    return ver[1];
  } else {
    ver = eregmatch(pattern: 'FIRMVER=[\\]"([0-9.]+)', string: vers);
    if (!isnull(ver[1])) {
      set_kb_item(name: "brother/printer/snmp/" + port + "/concludedFwOID", value: oid);
      return ver[1];
    }
  }
  return NULL;
}

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# nb: The model in sysdescr is bogus, not the real model
# Brother NC-8300h, Firmware Ver.1.08  (13.07.25),MID 8C5-F01,FID 2
if (sysdesc =~ "^Brother ") {
  model = "unknown";
  hw_version = "unknown";

  set_kb_item(name: "brother/printer/detected", value: TRUE);
  set_kb_item(name: "brother/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "brother/printer/snmp/port", value: port);
  set_kb_item(name: "brother/printer/snmp/" + port + "/banner", value: sysdesc);

  # Brother DCP-8112DN
  # Brother HL-L2395DW series
  model_description = get_kb_item("SNMP/" + port + "/model_description");
  mod = eregmatch(pattern: "^(Brother )?([^ \r\n]+).*", string: model_description);
  if (!isnull(mod[2])) {
    model = mod[2];
    model_description_oid = get_kb_item("SNMP/" + port + "/model_description/oid");
    set_kb_item(name: "brother/printer/snmp/" + port + "/concludedMod", value: mod[0]);
    set_kb_item(name: "brother/printer/snmp/" + port + "/concludedModOID", value: model_description_oid);
  }

  fw_oid = "1.3.6.1.4.1.2435.2.4.3.99.3.1.6.1.2.6";
  fw_version = extract_fw_version(oid: fw_oid, port: port);

  if (isnull(fw_version)) {
    fw_oid = "1.3.6.1.4.1.2435.2.4.3.99.3.1.6.1.2.8";
    fw_version = extract_fw_version(oid: fw_oid, port: port);
  }

  if (isnull(fw_version)) {
    fw_oid = "1.3.6.1.4.1.2435.2.4.3.99.3.1.6.1.2.7";
    fw_version = extract_fw_version(oid: fw_oid, port: port);
  }

  if (isnull(fw_version)) {
    fw_version = "unknown";
  }

  set_kb_item(name: "brother/printer/snmp/" + port + "/model", value: model);
  set_kb_item(name: "brother/printer/snmp/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "brother/printer/snmp/" + port + "/hw_version", value: hw_version);
}

exit(0);
