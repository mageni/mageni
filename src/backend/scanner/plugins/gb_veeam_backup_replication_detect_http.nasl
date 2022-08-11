###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_veeam_backup_replication_detect_http.nasl 5992 2017-04-20 14:42:07Z cfi $
#
# Veeam Backup & Replication Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105776");
  script_version("$Revision: 5992 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 16:42:07 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-06-22 11:05:14 +0200 (Wed, 22 Jun 2016)");
  script_name("Veeam Backup & Replication Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:9443 );
if( ! can_host_asp( port:port ) ) exit( 0 );

url = '/login.aspx';
buf = http_get_cache( item:url, port:port );

if ( "Veeam Backup Enterprise Manager : Login" >!< buf || "Veeam.CredentialsPanel" >!< buf ) exit ( 0 );

cpe = 'cpe:/a:veeam:backup_and_replication';
set_kb_item( name:"veeam_backup_and_replication/installed", value:TRUE);

vers = 'unknown';

version = eregmatch ( pattern:'\\.(css|js)\\?v=([0-9.]+[^"]+)"', string:buf );
if ( ! isnull ( version[2] ) ) {
  vers = version[2];
  cpe += ':' + vers;
}

register_product ( cpe:cpe, location:"/", port:port, service:'www' );
report = build_detection_report( app:"Veeam Backup & Replication", version:vers, install:"/", cpe:cpe, concluded:version[0] );
log_message( port:port, data:report );
exit( 0 );
