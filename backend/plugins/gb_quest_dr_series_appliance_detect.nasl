###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quest_dr_series_appliance_detect.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# Quest DR Series Appliance Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813011");
  script_version("$Revision: 10888 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-03-12 13:08:38 +0530 (Mon, 12 Mar 2018)");
  script_name("Quest DR Series Appliance Remote Detection");

  script_tag(name:"summary", value:"Detection of Quest DR Series Appliance.

  The script sends a connection request to the server and attempts to detect the
  presence of Quest DR Series Appliance.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

drPort = get_http_port(default:80);

res = http_get_cache(port:drPort, item:"/");
if('title="Quest Software Inc' >< res && 'ng-app="drConsoleApp' >< res &&
   '<dr-masthead-application-name>' >< res)
{
  version = "unknown";
  set_kb_item(name:"quest/dr/appliance/detected", value:TRUE);

  cpe = 'cpe:/a:quest:dr_appliance';
  register_product( cpe:cpe, location:"/", port:drPort,  service:"www");
  log_message(data: build_detection_report(app: "Quest DR Series Appliance", version:version, install: "/",
                                           cpe: cpe, concluded: "Quest DR Series Appliance Detected"),
                                           port: drPort);
  exit(0) ;
}
exit( 0 );
