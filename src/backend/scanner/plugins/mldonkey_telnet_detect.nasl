# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11124");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MLDonkey Detection (Telnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 4000);

  script_tag(name:"summary", value:"Telnet based detection of MLDonkey.");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("port_service_func.inc");

port = telnet_get_port(default: 4000);

banner = telnet_get_banner(port: port);

# Welcome to MLDonkey 3.1.3
# Welcome on mldonkey command-line
#
# Use ? for help
#
# MLdonkey command-line:

if (!banner || banner !~ "Welcome on mldonkey command\-line")
  exit(0);

version = "unknown";

set_kb_item(name: "mldonkey/detected", value: TRUE);
set_kb_item(name: "mldonkey/telnet/detected", value: TRUE);
set_kb_item(name: "mldonkey/telnet/port", value: port);
set_kb_item(name: "mldonkey/telnet/" + port + "/concluded", value: banner);

vers = eregmatch(pattern: "Welcome to MLDonkey ([0-9.]+)", string: banner, icase: TRUE);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "mldonkey/telnet/" + port + "/version", value: version);

exit(0);
