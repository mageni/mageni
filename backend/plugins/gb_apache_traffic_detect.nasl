###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# Apache Traffic Server Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Tim Brown <timb@openvas.org>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-03-29
# - Updated to set KB if Traffic Server is installed and grep all versions
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100796");
  script_version("$Revision: 10913 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-09-10 15:25:30 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Traffic Server Detection");

  script_tag(name:"summary", value:"Detects the installed version of
Apache Traffic Server.

The script sends a connection request to the web server and attempts to
extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ATS/banner");
  script_require_ports("Services/http_proxy", 8080, 3128, 80);
  exit(0);
}


include("http_func.inc");

include("cpe.inc");
include("host_details.inc");

http_port = get_kb_item("Services/http_proxy");
if(!http_port)http_port = 8080;

if(!get_port_state(http_port))exit(0);

banner = get_http_banner(port: http_port);
if(!banner || ("Server: ATS/" >!< banner && "ApacheTrafficServer" >!<  banner))exit(0);

## Extract version from Banner
version = eregmatch(pattern:"Server: ATS/([0-9.]+)",string:banner);
dir = "/";
dump = version;

if(version[1])
{
  ver = version[1];

  set_kb_item(name:"www/" + http_port + "/apache_traffic_server", value:ver);
  set_kb_item(name:"apache_trafficserver/version", value: ver);
  set_kb_item(name:"apache_trafficserver/installed",value:TRUE);

  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:apache:traffic_server:");
  if(!cpe)
    cpe = 'cpe:/a:apache:traffic_server';

  register_product(cpe:cpe, location:dir, port: http_port);

  log_message(data: build_detection_report(app: "ApacheTrafficServer", version: ver, install: dir, cpe: cpe,
                                           concluded: version[0]),
              port: http_port);
  exit(0);
}

exit(0);
