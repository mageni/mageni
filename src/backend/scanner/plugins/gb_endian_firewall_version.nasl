###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_endian_firewall_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Endian Firewall Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105391");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-01 12:50:18 +0200 (Thu, 01 Oct 2015)");
  script_name("Endian Firewall Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of Endian Firewall");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("endian_firewall/release");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! rls = get_kb_item( "endian_firewall/release" ) ) exit( 0 );
if( "Endian Firewall" >!< rls ) exit( 0 );

vers = 'unknown';
cpe = 'cpe:/a:endian_firewall:endian_firewall';

set_kb_item( name:"endian_firewall/installed", value:TRUE );

version = eregmatch( pattern:'Endian Firewall( Community)? release ([0-9]+\\.[^\r\n]+)', string:rls );

if( ! isnull( version[2] ) )
{
  vers = version[2];
  cpe += ':' + vers;
}

if( "Community" >< version[1] ) set_kb_item( name:"endian_firewall/community_edition", value:TRUE );

register_product( cpe:cpe, location:'ssh' );

log_message( data: build_detection_report( app:'Endian Firewall',
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:0 );

exit( 0 );


