# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170525");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-31 08:44:46 +0000 (Mon, 31 Jul 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fuji Xerox / Fujifilm Printer Detection (PJL)");

  script_tag(name:"summary", value:"Printer Job Language (PJL) based detection of Fuji Xerox / Fujifilm printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_pcl_pjl_detect.nasl");
  script_require_ports("Services/hp-pjl", 9100);
  script_mandatory_keys("hp-pjl/banner/available");

  exit(0);
}

port = get_kb_item("hp-pjl/port");

banner = get_kb_item("hp-pjl/" + port + "/banner");
if(!banner || !egrep(pattern: "^(FUJI XEROX|FUJIFILM|FX DocuPrint) ", string: banner, icase: TRUE))
  exit(0);

set_kb_item(name: "fujifilm/printer/detected", value: TRUE);
set_kb_item(name: "fujifilm/printer/hp-pjl/detected", value: TRUE);
set_kb_item(name: "fujifilm/printer/hp-pjl/port", value: port);
set_kb_item(name: "fujifilm/printer/hp-pjl/" + port + "/concluded", value: banner);

if(banner =~ "^(FUJI XEROX|FUJIFILM)") {
  # FUJI XEROX ApeosPort-V C5576
  # FUJIFILM Apeos C3070
  mod = eregmatch(pattern: "^(FUJI XEROX|FUJIFILM) (.*)", string: banner, icase: TRUE);
  if(!isnull(mod[2]))
    set_kb_item(name: "fujifilm/printer/hp-pjl/" + port + "/model", value: mod[2]);
} else {
  # FX DocuPrint P115 w:84U-E07:Ver.1.05
  # FX DocuPrint M225 dw:8C5-HA3:Ver.G
  mod = eregmatch(pattern: "^FX (DocuPrint [^:]+):", string: banner, icase: TRUE);
  if(!isnull(mod[1]))
    set_kb_item(name: "fujifilm/printer/hp-pjl/" + port + "/model", value: mod[1]);
  ver = eregmatch(pattern: ":Ver\.([A-Z0-9.]+)", string: banner, icase: TRUE);
  if(!isnull(ver[1]))
    set_kb_item(name: "fujifilm/printer/hp-pjl/" + port + "/fw_version", value: ver[1]);
}
exit(0);
