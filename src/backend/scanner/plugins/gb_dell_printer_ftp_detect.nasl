# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151377");
  script_version("2023-12-14T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-12-14 05:05:32 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-12 05:14:40 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell Printer Detection (FTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/dell/printer/detected");

  script_tag(name:"summary", value:"FTP based detection of Dell printer devices.");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);

banner = ftp_get_banner(port: port);

# 220 Dell MFP S2815dn
# 220 Dell MFP Laser 3115cn
# 220 Dell Color MFP H625cdw
# 220 Dell Laser Printer 5100cn
# 220 Dell Color Laser 3110cn
# Dell C3760dn Color Laser
if (!banner || banner !~ "Dell .*(Laser|MFP|Printer)")
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name: "dell/printer/detected", value: TRUE);
set_kb_item(name: "dell/printer/ftp/detected", value: TRUE);
set_kb_item(name: "dell/printer/ftp/port", value: port);
set_kb_item(name: "dell/printer/ftp/" + port + "/concluded", value: banner);

mod = eregmatch(pattern: "Dell (.*)( Laser|Printer)?", string: banner);
if (!isnull(mod[1])) {
  model = mod[1];
  model = str_replace(string: model, find: " Printer", replace: "");
  model = str_replace(string: model, find: "  ", replace: " ");
  model = chomp(model);
}

set_kb_item(name: "dell/printer/ftp/" + port + "/model", value: model);
set_kb_item(name: "dell/printer/ftp/" + port + "/version", value: version);

exit(0);
