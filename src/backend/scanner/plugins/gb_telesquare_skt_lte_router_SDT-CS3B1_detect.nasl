###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_telesquare_skt_lte_router_SDT-CS3B1_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# Telesquare SKT LTE Router SDT-CS3B1 Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812366");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-12-28 10:46:29 +0530 (Thu, 28 Dec 2017)");
  script_name("Telesquare SKT LTE Router SDT-CS3B1 Detection");

  script_tag(name:"summary", value:"Detection of Telesquare SKT LTE Router SDT-CS3B1.

  The script sends a connection request to the server and attempts to detect the
  presence of the router.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

ltePort = get_http_port(default:80);
res = http_get_cache( port:ltePort, item: "/" );

if("value='login'" >< res && "<title>Login to SDT-CS3B1<" >< res)
{
  version = "unknown";
  install = ltePort + "/tcp";

  set_kb_item( name:"telesquare/SDT-CS3B1/detected", value:TRUE );

  ##CPE not found, Creating new cpe
  cpe = "cpe:/h:telesquare:sdt-cs3b1";

  register_product(cpe:cpe, location:install, port:ltePort);

  log_message(data: build_detection_report(app: "Telesquare SKT LTE Router SDT-CS3B1",
                                           version: version,
                                           install: install,
                                           cpe: cpe,
                                           concluded: version),
                                           port: ltePort);
  exit(0);
}
exit(0);
