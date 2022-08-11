###############################################################################
# OpenVAS Vulnerability Test
# $Id: support_incident_tracker_detect.nasl 11591 2018-09-25 08:09:20Z asteins $
#
# SiT! Support Incident Tracker Detection
#
# Authors:
# Michael Meyer
#
# Updated by Madhuri D <dmadhuri@secpod.com> on 2011-07-28
#   - Modified the regex for detecting p1 versions.
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-02-03
#  - Updated to set KB if SIT is installed
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
  script_oid("1.3.6.1.4.1.25623.1.0.100466");
  script_version("$Revision: 11591 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 10:09:20 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("SiT! Support Incident Tracker Detection");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"qod_type", value:"remote_banner");

  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running SiT! Support Incident Tracker, a web based
  application which uses PHP and MySQL for tracking technical support calls/emails.");

  script_xref(name:"URL", value:"http://sitracker.org/wiki/Main_Page");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( !can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/tracker", "/support", "/sit", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL ) continue;

  if( egrep( pattern:'<meta name="GENERATOR" content="SiT! Support Incident Tracker', string:buf, icase:TRUE ) &&
    "SiT! - Login" >< buf ) {

    set_kb_item( name:"sit/installed", value:TRUE );

    version = "unknown";
    version_match = eregmatch( string:buf, pattern:"Support Incident Tracker v(([0-9.]+).?([a-zA-Z0-9]+))", icase:TRUE );
    if ( !isnull(version_match[1] ) ) {
      version = ereg_replace( pattern:" |-", string:version_match[1], replace:"." );
      concluded_url = report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    set_kb_item( name:"www/" + port + "/support_incident_tracker", value:version );

    register_and_report_cpe( app:"SiT! Support Incident Tracker", ver:version, base:"cpe:/a:sitracker:support_incident_tracker:",
                            expr:"^([0-9.]+)", insloc:install, regPort:port, conclUrl: concluded_url );
    exit( 0 );
  }
}

exit( 0 );
