###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dnaLIMS_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# dnaLIMS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140182");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-13 16:23:57 +0100 (Mon, 13 Mar 2017)");
  script_name("dnaLIMS Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/cgi-bin/dna/password.cgi';

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Login to dnaLIMS" >< buf && "dnaTools, All Rights Reserved" >< buf )
{
  cpe = 'cpe:/a:dnatools:dnalims';
  vers = 'unknown';

  set_kb_item( name:'dnaTools/dnaLIMS/installed', value:TRUE );

  # 4-2015s14
  # 1-300s59d29i15
  # 4-2016s8
  # 2-600s4
  v = eregmatch( pattern:'color="#999999"> ([0-9]-[^ <]+) </font>', string:buf );
  if( ! isnull( v[1] ) && v[1] =~ '^[0-9-]' )
  {
    vers = v[1];
    set_kb_item( name:'dnaTools/dnaLIMS/version', value:vers);
    cpe += ':' + vers;
  }

  register_product( cpe:cpe, location:url, port:port, service:"www" );
  report = build_detection_report( app:'dnaTools dnaLIMS', version:vers, install:'/cgi-bin/dna/', cpe:cpe, concluded:v[0], concludedUrl:url);
  log_message( port:port, data:report );
}

exit( 0 );
