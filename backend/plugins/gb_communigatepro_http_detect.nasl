###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_communigatepro_http_detect.nasl 13140 2019-01-18 08:26:06Z asteins $
#
# CommuniGatePro Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140685");
  script_version("$Revision: 13140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 09:26:06 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-01-15 15:48:28 +0700 (Mon, 15 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CommuniGate Pro Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of CommuniGate Pro.

The script sends a connection request to the server and attempts to detect CommuniGate Pro and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 443, 8010);
  script_mandatory_keys("CommuniGatePro/banner");

  script_xref(name:"URL", value:"https://www.communigate.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");


port = get_http_port(default: 8010);

banner = get_http_banner(port: port);
if ("CommuniGatePro/" >!< banner)
  exit(0);

set_kb_item(name: "communigatepro/detected", value: TRUE);
set_kb_item(name: "communigatepro/http/detected", value: TRUE);
set_kb_item(name: "communigatepro/http/port", value: port);

vers = eregmatch(pattern: "CommuniGatePro/([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "communigatepro/http/" + port + "/version", value: version);
  set_kb_item(name: "communigatepro/http/" + port + "/concluded", value: vers[0]);
}

exit(0);
