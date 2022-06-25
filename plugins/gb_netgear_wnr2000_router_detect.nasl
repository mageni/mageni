###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_wnr2000_router_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# NETGEAR WNR2000 Routers Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.809774");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-30 14:43:15 +0530 (Fri, 30 Dec 2016)");
  script_name("NETGEAR WNR2000 Routers Detection");

  script_tag(name:"summary", value:"Detection of NETGEAR WNR2000 Routers

  The script sends a connection request to the server and attempts to
  detect the presence of NETGEAR WNR2000 Routers.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wnr2000/banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");


netPort = get_http_port(default:80);

banner = get_http_banner(port:netPort);

if(banner && 'WWW-Authenticate: Basic realm="NETGEAR wnr2000' >< banner)
{
  location = "/";
  version = "Unknown";

  set_kb_item(name: "netgear_wnr2000/detected", value: TRUE);

  ##CPE not available, building cpe name as cpe:/h:netgear:wnr2000
  cpe = "cpe:/h:netgear:wnr2000";

  register_product(cpe:cpe, location:location, port:netPort);

  log_message(data: build_detection_report(app: "NETGEAR wnr2000 Router",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: version),
                                           port: netPort);
  exit(0);
}
