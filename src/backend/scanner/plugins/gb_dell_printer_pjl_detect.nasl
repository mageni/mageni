# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151375");
  script_version("2023-12-14T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-12-14 05:05:32 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-12 03:47:04 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell Printer Detection (PJL)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_pcl_pjl_detect.nasl");
  script_require_ports("Services/hp-pjl", 9100);
  script_mandatory_keys("hp-pjl/banner/available");

  script_tag(name:"summary", value:"Printer Job Language (PJL) based detection of Dell printer
  devices.");

  exit(0);
}

port = get_kb_item("hp-pjl/port");

banner = get_kb_item("hp-pjl/" + port + "/banner");
if (!banner || banner !~ "Dell ")
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name: "dell/printer/detected", value: TRUE);
set_kb_item(name: "dell/printer/hp-pjl/detected", value: TRUE);
set_kb_item(name: "dell/printer/hp-pjl/port", value: port);
set_kb_item(name: "dell/printer/hp-pjl/" + port + "/concluded", value: banner);

# Dell MFP H815dw
# Dell Color MFP S2825cdn
# Dell 2135cn MFP
# Dell B2360dn Laser Printer
mod = eregmatch(pattern: "^Dell (.*)( Laser|Printer)?", string: banner);
if (!isnull(mod[1]))
  model = chomp(mod[1]);

set_kb_item(name: "dell/printer/hp-pjl/" + port + "/model", value: model);
set_kb_item(name: "dell/printer/hp-pjl/" + port + "/version", value: version);

exit(0);
