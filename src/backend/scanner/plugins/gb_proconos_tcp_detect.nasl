# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140498");
  script_version("2023-09-22T16:08:59+0000");
  script_tag(name:"last_modification", value:"2023-09-22 16:08:59 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-11-13 10:14:34 +0700 (Mon, 13 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ProConOS Service Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(20547);

  script_tag(name:"summary", value:"TCP based detection of a ProConOS service.");

  script_tag(name:"insight", value:"ProConOS is a high performance PLC run time engine designed for
  both embedded and PC based control applications.");

  script_xref(name:"URL", value:"https://www.plantautomation.com/doc/proconos-0001");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = 20547;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

# info query (see https://github.com/digitalbond/Redpoint/blob/master/proconos-info.nse)
query = raw_string(0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x00, 0x47, 0xee);
send(socket: soc, data: query);
recv = recv(socket: soc, length: 1024);
close(soc);

if (!recv)
  exit(0);

if ((hexstr(substr(recv, 0, 1)) != "cc01") || (strlen(recv) < 105)) {
  unknown_banner_set(port: port, banner: recv, set_oid_based: TRUE);
  exit(0);
}

# Ladder Logic Runtime
# e.g.
# ProConOS V4.1.0267 Jul 31 2012
# ProConOS V4.1.280 Sep 15 2021
# ProConOS V4.0.0059 May 10 2005
# ProConOS V4.1.0198i Nov 17 2010
llr = bin2string(ddata: substr(recv, 12, 43), noprint_replacement: "");
set_kb_item(name: "proconos/llr", value: llr);

# PLC Type
# e.g.
# Bristol: CWM V05:50:00 07/31
# Bristol: E3L V06:01:00 09/15
# Bristol: CWM V04:41:00 05/10
# V 3.52T.8       02/13/09
# FCN/FCJ Jun 13 2012
# ADAM-5560 CE ARM V4.00.14
type = bin2string(ddata: substr(recv, 44, 75), noprint_replacement: "");
set_kb_item(name: "proconos/type", value: type);

# Project Name
# e.g. 28Commercia
prj_name = bin2string(ddata: substr(recv, 76, 87), noprint_replacement: "");

# Boot Project
# e.g. 28Commercia
boot_prj = bin2string(ddata: substr(recv, 88, 99), noprint_replacement: "");

# Project Source Code
# e.g.
# Exist
# None
src = bin2string(ddata: substr(recv, 100, 105), noprint_replacement: "");

set_kb_item(name: "proconos/detected", value: TRUE);
set_kb_item(name: "proconos/tcp/detected", value: TRUE);

service_register(port: port, proto: "proconos");

report = 'A ProConOS service is running at this port.\n\nThe following information was extracted:\n\n' +
         "Ladder Logic Runtime:  " + llr + '\n' +
         "PLC Type:              " + type + '\n' +
         "Project Name:          " + prj_name + '\n' +
         "Boot Project:          " + boot_prj + '\n' +
         "Project Source Code:   " + src;

log_message(port: port, data: report);

exit(0);
