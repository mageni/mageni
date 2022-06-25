##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_broadwin_webaccess_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# BroadWin WebAccess Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.105327");
  script_version("$Revision: 10908 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-08-20 17:37:34 +0200 (Thu, 20 Aug 2015)");
  script_name("BroadWin WebAccess Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of BroadWin WebAccess.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

awPort = get_http_port( default:80 );
if( ! can_host_asp( port:awPort ) ) exit( 0 );

awRes = http_get_cache( item:"/broadWeb/bwRoot.asp", port:awPort );

if( "<title>BroadWin WebAccess" >!< awRes && " BroadWin Technology, Inc." >!< awRes ) {
  exit( 0 );
}

vers = 'unknown';
cpe = 'cpe:/a:broadwin:webaccess';

awVer = eregmatch(pattern:"Software Build : ([0-9.-]+)", string:awRes); # 7.0-2011.07.13
if( ! isnull( awVer[1] ) ) {
  vers = str_replace( string:awVer[1], find:"-", replace:".");
  cpe += ':' + vers;
}

set_kb_item(name:"www/" + awPort + "/BroadWin/WebAccess", value:vers);
set_kb_item(name:"BroadWin/WebAccess/installed", value:TRUE);

register_product(cpe:cpe, location:awPort + '/tcp', port:awPort);

log_message(data: build_detection_report(app:"BroadWin WebAccess",
                                         version:vers,
                                         install:'/broadWeb/',
                                         cpe:cpe,
                                         concluded: awVer[0]),
                                         port:awPort);
