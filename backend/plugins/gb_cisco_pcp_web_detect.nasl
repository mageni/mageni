###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_pcp_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Prime Collaboration Provisioning Web Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105548");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-16 10:35:13 +0100 (Tue, 16 Feb 2016)");
  script_name("Cisco Prime Collaboration Provisioning Web Detection");

  script_tag(name:"summary", value:"This Script performs HTTP(s) based detection of the Cisco Prime Collaboration Provisioning Web Interface");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

buf = http_get_cache( port:port, item:"/" );

if( buf =~ "HTTP/1.. 302" && "/cupm/Login" >< buf )
{
  cpe = 'cpe:/a:cisco:prime_collaboration_provisioning';
  vers = 'unknown';

  url = '/dfcweb/lib/cupm/nls/applicationproperties.js';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "Cisco Prime Collaboration" >!< buf ) exit( 0 );

  set_kb_item( name:"cisco/cupm/http/version", value:vers );
  set_kb_item( name:"cisco/cupm/http/port", value:port );

  # not granular enough for later use. Detected via ssh: 10.0.0.791, detected via http: 10.0
  version = eregmatch( pattern:'file_version: "Version ([^"]+)",', string:buf );
  if( ! isnull( version[1] ) )
  {
    vers = version[1];
    cpe += ':' + vers;
  }

  report = 'The Cisco Prime Collaboration Provisioning Web Interface is running at this port.\n' +
           'Version: ' + vers + '\n' +
           'CPE: ' + cpe + '\n';

  log_message( port:port, data:report );
  exit( 0 );

}

exit( 0 );

