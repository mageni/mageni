# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170551");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-22 14:43:18 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brother Printer Detection (PJL)");

  script_tag(name:"summary", value:"Printer Job Language (PJL) based detection of Brother printer
  devices.");

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
if (!banner || banner !~ "^Brother")
  exit(0);

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "brother/printer/detected", value: TRUE);
set_kb_item(name: "brother/printer/hp-pjl/detected", value: TRUE);
set_kb_item(name: "brother/printer/hp-pjl/port", value: port);
set_kb_item(name: "brother/printer/hp-pjl/" + port + "/concluded", value: banner);

# Brother HL-L2370DN series:84U-H7G:Ver.1.35
# Brother MFC-L2710DN series:8C5-K6G:Ver.J
mod = eregmatch(pattern: "^Brother ([^ ]+)", string: banner);
if (!isnull(mod[1]))
  model = mod[1];

ver = eregmatch(pattern: ":Ver\.([A-Z0-9.]+)", string: banner);
if (!isnull(ver[1]))
  fw_version = ver[1];

set_kb_item(name: "brother/printer/hp-pjl/" + port + "/model", value: model);
set_kb_item(name: "brother/printer/hp-pjl/" + port + "/fw_version", value: fw_version);

exit(0);