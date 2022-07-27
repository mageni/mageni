###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_up_time_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# up.time Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103147");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("up.time Detection");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9999);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"This host is running up.time, a server monitoring software.");
  script_xref(name:"URL", value:"http://www.uptimesoftware.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

url = "/index.php";
buf = http_get_cache(item:url, port:port);
if( buf == NULL )exit(0);

if("<title>up.time" >< buf && ( "Please Enter Your Username and Password to Log In:" >< buf || "/styles/uptime.css" >< buf ) ){

  install = "/";
  vers = "unknown";

  version = eregmatch( pattern:'<li>up.time ([^ ]+) \\(build ([^)]+)\\)</li>', string:buf );
  if( isnull( version[1] ) )
     version = eregmatch( pattern:'/styles/uptime.css\\?v=([0-9.]+).([0-9]+)', string:buf );

  if( ! isnull( version[1] ) ) vers = version[1];
  if( ! isnull( version[2] ) ) build = version[2];

  set_kb_item(name: string("www/", port, "/up.time"), value: string(vers," under ",install));
  set_kb_item( name:"up.time/installed", value:TRUE );
  set_kb_item( name:"up.time/port", value:port );
  set_kb_item( name:"up.time/" + port + '/version', value:vers );
  if( build )
    set_kb_item( name:"up.time/" + port + '/build', value:build );

  report = 'Detected up.time version ' + vers;
  if( build ) report += ' Build (' + build + ')';
  report += '\nLocation: ' + url + '\n';

  log_message(port:port, data:report);
  exit(0);
}

exit(0);

