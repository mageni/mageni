# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149718");
  script_version("2023-05-26T16:08:11+0000");
  script_tag(name:"last_modification", value:"2023-05-26 16:08:11 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-24 04:35:40 +0000 (Wed, 24 May 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Printer Detection (GGW)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_generic_scan_gateway_detect.nasl");
  script_require_ports("Services/hp-gsg", 9220);
  script_mandatory_keys("ggw/detected");

  script_tag(name:"summary", value:"Generic Scan Gateway (GGW) based detection of HP printer
  devices.");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = service_get_port(default: 9220, proto: "hp-gsg");

devinfo = get_kb_item("ggw/" + port + "/device_info");
if (!devinfo || "MFG:HP;" >!< devinfo)
  exit(0);

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "hp/printer/detected", value: TRUE);
set_kb_item(name: "hp/printer/ggw/detected", value: TRUE);
set_kb_item(name: "hp/printer/ggw/port", value: port);
set_kb_item(name: "hp/printer/ggw/" + port + "/device_info", value: devinfo);

# 255 MFG:HP;MDL:OfficeJet 3830 series;CMD:PCL3GUI,PJL,Automatic,JPEG,PCLM,AppleRaster,PWGRaster,DW-PCL,802.11,DESKJET,DYN;CLS:PRINTER;DES:K7V40A;CID:hpijvipav7;LEDMDIS:USB#FF#CC#00,USB#07#01#02,USB#FF#04#01;SN:<redacted>;S:038000C480a00001002c2400064c140005a;Z:05000009000009,12000,17000000000000,181;
mod = eregmatch(pattern: "MDL:([^;]+);", string: devinfo);
if (!isnull(mod[1])) {
  model = mod[1];
  model = str_replace(string: model, find: " series", replace: "");
}

set_kb_item(name: "hp/printer/ggw/" + port + "/model", value: model);
set_kb_item(name: "hp/printer/ggw/" + port + "/fw_version", value: fw_version);

exit(0);
