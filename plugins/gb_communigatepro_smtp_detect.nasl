###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_communigatepro_smtp_detect.nasl 13470 2019-02-05 12:39:51Z cfischer $
#
# CommuniGatePro Detection (SMTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140686");
  script_version("$Revision: 13470 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 13:39:51 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-01-15 15:48:28 +0700 (Mon, 15 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CommuniGate Pro Detection (SMTP)");

  script_tag(name:"summary", value:"Detection of CommuniGate Pro.

This script performs SMTP based detection of CommuniGate Pro.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 587);
  script_mandatory_keys("smtp/communigate/pro/detected");

  script_xref(name:"URL", value:"https://www.communigate.com/");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");

port = get_smtp_port(default: 25);

banner = get_smtp_banner(port: port);

if ("CommuniGate Pro" >!< banner)
  exit(0);

set_kb_item(name: "communigatepro/detected", value: TRUE);
set_kb_item(name: "communigatepro/smtp/detected", value: TRUE);
set_kb_item(name: "communigatepro/smtp/port", value: port);

vers = eregmatch(pattern: "CommuniGate Pro ([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "communigatepro/smtp/" + port + "/version", value: version);
  set_kb_item(name: "communigatepro/smtp/" + port + "/concluded", value: vers[0]);
}

exit(0);
