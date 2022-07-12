###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_tv_version.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Apple TV Version Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140000");
  script_version("$Revision: 10911 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-09-28 12:12:23 +0200 (Wed, 28 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apple TV Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_apple_tv_detect.nasl");
  script_require_ports("Services/www", 7000);
  script_mandatory_keys("apple_tv/detected");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:7000 );

# http://nto.github.io/AirPlay.html#video-httprequests
url = '/server-info';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "AppleTV" >!< buf ) exit( 0 );

m = eregmatch( pattern:'<key>model</key>\\s*\n*<string>AppleTV([0-9]+,[0-9]+)</string>', string:buf );
if( isnull( m[1] ) ) exit( 0 );

model = m[1];

b = eregmatch( pattern:'<key>osBuildVersion</key>\\s*\n*<string>([^<]+)</string>', string:buf );
if( isnull( b[1] ) ) exit( 0 );

build = b[1];

register_and_report_os( os:"Apple TV", cpe:"cpe:/o:apple:tv", banner_type:"HTTP banner", port:port, desc:"Apple TV Version Detection", runs_key:"unixoide" );

ma = eregmatch( pattern:'<key>macAddress</key>\\s*\n*<string>([^<]+)</string>', string:buf );
if( ! isnull( ma[1] ) )
  register_host_detail(name:"MAC", value:ma[1], desc:"Apple TV Version Detection");

report = 'Model:     ' + model + '\n' + 'Build:     ' + build + '\n' + 'CPE:       cpe:/o:apple:tv\nConcluded: ' + report_vuln_url(  port:port, url:url, url_only:TRUE ) + '\n';

log_message( port:port, data:'The following information could be gathered from the remote Apple TV device:\n\n' + report );
exit( 0 );

