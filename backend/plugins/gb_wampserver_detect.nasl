###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wampserver_detect.nasl 9149 2018-03-20 12:26:00Z jschulte $
#
# WampServer Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800297");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-20 13:26:00 +0100 (Tue, 20 Mar 2018) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("WampServer Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed WampServer version and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

wampPort = get_http_port(default:80);

if( ! can_host_php( port:wampPort ) ) exit( 0 );

rcvRes = http_get_cache(item: "/index.php", port:wampPort);

if("title>WAMPSERVER" >!< rcvRes) exit( 0 );

wv = 'unknown';
cpe = 'cpe:/a:wampserver:wampserver';

wampVer = eregmatch(pattern:">[vV]ersion ([0-9.a-z]+)" , string:rcvRes);

if(wampVer[1] != NULL)
{
  wv = wampVer[1];
  cpe += ':' + wv;
}

set_kb_item(name:"www/" + wampPort + "/WampServer", value:wv);
set_kb_item(name:"wampserver/installed", value:TRUE );

register_product( cpe:cpe, location:"/", port:wampPort, service:'www' );

report = build_detection_report( app:"WampServer", version:wv, install:"/", cpe:cpe, concluded:wampVer[0], concludedUrl:"/index.php" );

log_message( port:wampPort, data:report );
exit( 0 );

