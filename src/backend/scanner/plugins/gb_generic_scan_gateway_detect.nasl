# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149717");
  script_version("2023-05-26T16:08:11+0000");
  script_tag(name:"last_modification", value:"2023-05-26 16:08:11 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-24 03:41:34 +0000 (Wed, 24 May 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Generic Scan Gateway (GGW) Service Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/hp-gsg", 9220);

  script_tag(name:"summary", value:"A Generic Scan Gateway (GGW) service is running at this host.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default: 9220, proto: "hp-gsg");

if (!soc = open_sock_tcp(port))
  exit(0);

banner = recv(socket: soc, length: 512);
if (!banner || !egrep(string: banner, pattern: "^220 (HP|JetDirect) GGW server")) {
  close(soc);
  exit(0);
}

set_kb_item(name: "ggw/detected", value: TRUE);

report = "A Generic Scan Gateway (GGW) server service is running at this port." +
         '\n\nBanner:\n' + chomp(banner);

send(socket: soc, data: 'devi\n');
devinfo = recv(socket: soc, length: 2048);

close(soc);

devinfo = chomp(devinfo);
if (devinfo) {
  set_kb_item(name: "ggw/" + port + "/device_info", value: devinfo);
  report += '\n\nDevice Info:\n' + devinfo;
}

log_message(port: port, data: report);

exit(0);
