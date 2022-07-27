###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_wifimanger_detect.nasl 13674 2019-02-15 03:34:06Z ckuersteiner $
#
# D-Link Central WiFiManager Software Controller Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141570");
  script_version("$Revision: 13674 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 04:34:06 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-10-05 11:56:43 +0700 (Fri, 05 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link Central WiFiManager Software Controller Detection (HTTP");

  script_tag(name:"summary", value:"Detection of D-Link Central WiFiManager Software Controller.

The script sends a HTTP connection request to the server and attempts to detect D-Link Central WiFiManager
Software Controller.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

if (!can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/Lang/en-US/common.js");

if ("Central WiFiManager" >< res) {
  set_kb_item(name: "dlink_central_wifimanager/detected", value: TRUE);
  set_kb_item(name: "dlink_central_wifimanager/http/port", value: port);

  exit(0);
}

exit(0);
