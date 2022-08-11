###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iball_baton_150m_wireless_router_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# iBall Baton 150M Wireless Router Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811312");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-08-31 11:28:00 +0530 (Thu, 31 Aug 2017)");
  script_name("iBall Baton 150M Wireless Router Detection");

  script_tag(name:"summary", value:"Detection of iBall Baton 150M Wireless
  Router.

  The script sends a connection request to the server and attempts to
  detect the presence of iBall Baton 150M Wireless Router.");

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

netPort = get_http_port(default:80);
banner = get_http_banner(port:netPort);

if(banner && 'WWW-Authenticate: Basic realm="iBall Baton 150M Wireless-N ADSL2+ Router' >< banner)
{
  location = "/";
  version = "Unknown";

  set_kb_item(name:"iBall_Baton_150M_Router/detected", value: TRUE);

  cpe = "cpe:/h:iball:baton_150m_wireless-n_router";


  register_product(cpe:cpe, location:location, port:netPort);

  log_message(data: build_detection_report(app: "iBall Baton 150M Wireless Router",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: version),
                                           port: netPort);
  exit(0);
}
