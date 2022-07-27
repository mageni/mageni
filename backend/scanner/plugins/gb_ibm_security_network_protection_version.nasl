###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_security_network_protection_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# IBM Security Network Protection Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105746");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-01 15:10:02 +0200 (Wed, 01 Jun 2016)");
  script_name("IBM Security Network Protection Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of IBM Security Network Protection");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("isnp/detected");
  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

firmware = ssh_cmd( socket:sock, cmd:'firmware list', nosh:TRUE, pty:TRUE, timeout:30, retry:10 );

if( "Firmware Version:" >!< firmware ) exit( 0 );
vers = "unknown";
cpe = 'cpe:/a:ibm:security_network_protection';

fw = split( firmware, keep:FALSE );

for( i=0; i < max_index( fw ); i++ )
{
  if( "ACTIVE" >< fw[i] )
  {
    version = eregmatch( pattern:'IBM Security Network Protection ([0-9]+[^\r\n]+)', string:fw[i + 1]);
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      cpe += ':' + vers;
    }
    break;
  }
}

set_kb_item( name:"isnp/version", value:vers );

register_product( cpe:cpe, location:"ssh" );

report = build_detection_report( app:"IBM Security Network Protection", version:vers, install:"ssh", cpe:cpe, concluded:"firmware list" );
log_message( port:0, data:report );

exit( 0 );

