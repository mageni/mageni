# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170524");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-31 08:44:46 +0000 (Mon, 31 Jul 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fuji Xerox / Fujifilm Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Fuji Xerox / Fujifilm printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if(!sysdesc)
  exit(0);

# Some Xerox printers return a hex representative
# e.g. 58 65 72 6F 78 C2 AE 20 43 6F 6C 6F 72 20 31 30 ...
# Change back to a string and remove unprintable chars
if(sysdesc =~ "^[0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}") {
  sysdesc = hex2str(str_replace(string: sysdesc, find: " ", replace: ""));
  sysdesc = bin2string(ddata: sysdesc, noprint_replacement: "");
}

# FUJI XEROX DocuPrint CM305 df; ...
# FUJIFILM ApeosPort C2410SD; ...
# nb:
# - Keep in sync with the pattern used in dont_print_on_printers.nasl
# - Case insensitive match (via "=~") is expected / done on purpose as different writings of XEROX
#   vs. Xerox has been seen
if(sysdesc =~ "^(FUJI XEROX|FUJIFILM) ") {
  set_kb_item(name: "fujifilm/printer/detected", value: TRUE);
  set_kb_item(name: "fujifilm/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "fujifilm/printer/snmp/port", value: port);
  set_kb_item(name: "fujifilm/printer/snmp/" + port + "/concluded", value: sysdesc);

  # FUJI XEROX DocuColor 1450 GA ;ESS1.102.18,IOT 72.51.0,HCF 3.33.0,FIN C18.29.0,IIT 7.10.0,ADF 21.3.0,SJFI3.0.17,SSMI1.15.2
  mod = eregmatch(pattern: "(FUJI XEROX|FUJIFILM) ([^;]+);?", string: sysdesc);
  if(!isnull(mod[2])) {
    if(";" >!< mod[0] && sysdesc !~ "FUJIFILM") {
      # Likely extracted from hex response so just take the first part
      model = split(mod[2], sep: " ", keep: FALSE);
      set_kb_item(name: "fujifilm/printer/snmp/" + port + "/model", value: model[0]);
    } else {
      set_kb_item(name: "fujifilm/printer/snmp/" + port + "/model", value: mod[2]);
    }
  }

  # FUJI XEROX ApeosPort C4570; System 22.1.7, ESS 1.60.9, IOT 22.50.0, ADF 23.26.0, Fax 2.2.1, Panel 30.109.16, Boot 1.0.101, Contents 4.7.26, Plugin 4.7.26
  vers = eregmatch(pattern: "[;,] ?System ([0-9.]+)", string: sysdesc);
  if(!isnull(vers[1])) {
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }

  # FUJI XEROX DocuPrint CP505 d; Controller 1.140.2, IOT 2.22.0, IOT2 4.8.0, Panel 92.16.11, Boot 1.1.200
  vers = eregmatch(pattern: "[;,] ?Controller ([0-9.]+)", string: sysdesc);
  if(!isnull(vers[1])) {
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }

  # FUJI XEROX DocuPrint CM305 df; Net 16.41,ESS 201210101131,IOT 03.00.05
  # FUJI XEROX ApeosPort-IV C3375 ;ESS1.131.3,IOT 84.14.0,ADF 7.16.0,FAX 1.1.14,BOOT 1.0.54,SJFI3.3.0,SSMI1.20.1
  vers = eregmatch(pattern: "ESS( )?([0-9.]+),", string: sysdesc);
  if(!isnull(vers[2])) {
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/fw_version", value: vers[2]);
    exit(0);
  }

  # FUJIFILM ApeosPort C2410SD; version CXLBL.076.024 kernel 4.17.19-yocto-standard-9b7c8a0e4f5f02470de2620d0912f67e All-N-
  vers = eregmatch(pattern: "version( )?([A-Z0-9.]+)", string: sysdesc);
  if(!isnull(vers[2])) {
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/fw_version", value: vers[2]);
    exit(0);
  }

  # System 23.1.23; ESS 1.3.1; IOT 10.36.0; Finisher A 4.26.0; ADF 32.19.0; Fax 2.2.1; Panel 1.1.4; IPS Accelerator 21.9.0; Boot 1.0.155; Contents 5.0.32; Plugin 5.0.32
  ver_oid = "1.3.6.1.4.1.297.1.111.1.31.10.0";
  v = snmp_get(port: port, oid: ver_oid);

  ver = eregmatch(pattern: "System ([0-9.]+);", string: v);
  if(!isnull(ver[1])) {
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/fw_version", value: ver[1]);
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/concludedFwOID", value: ver_oid);
  }

  exit(0);
}

# FX DocuPrint P115 w, ...
# nb: Keep in sync with the pattern used in dont_print_on_printers.nasl
else if(sysdesc =~ "^FX DocuPrint ") {
  set_kb_item(name: "fujifilm/printer/detected", value: TRUE);
  set_kb_item(name: "fujifilm/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "fujifilm/printer/snmp/port", value: port);
  set_kb_item(name: "fujifilm/printer/snmp/" + port + "/concluded", value: sysdesc);
  # FX DocuPrint P115 w, Firmware Ver.D  ,MID 84U-E07
  mod = eregmatch(pattern: "FX ([^,;]+)[;,]?", string: sysdesc);
  if(!isnull(mod[1]))
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/model", value: mod[1]);

  vers = eregmatch(pattern: "[;,] ?Firmware Ver\. ?([A-Z0-9.]+)", string: sysdesc);
  if(!isnull(vers[1]))
    set_kb_item(name: "fujifilm/printer/snmp/" + port + "/fw_version", value: vers[1]);
}

exit(0);
