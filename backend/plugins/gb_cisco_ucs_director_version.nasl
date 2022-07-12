###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_director_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco UCS Director Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105575");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-17 15:52:18 +0100 (Thu, 17 Mar 2016)");
  script_name("Cisco UCS Director Version Detection");

  script_tag(name:"summary", value:"This script performs ssh based detection of Cisco UCS Director");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_ucs_director/show_version");
  exit(0);
}


include("host_details.inc");

show_version = get_kb_item( "cisco_ucs_director/show_version" );
if( ! show_version ) exit( 0 );

cpe = 'cpe:/a:cisco:ucs_director';
vers = 'unknown';

version = eregmatch( pattern:'Version\\s*:\\s*([0-9]+[^\r\n]+)', string:show_version );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  rep_vers = vers;
  cpe += ':' + vers;
  set_kb_item( name:"cisco_ucs_director/version", value:vers );
}

build = eregmatch( pattern:'Build Number\\s*:\\s*([0-9]+[^\r\n]+)', string:show_version );
if( ! isnull( build[1] ) )
{
  set_kb_item( name:"cisco_ucs_director/build", value:build[1] );
  rep_vers += ' Build ' + build[1];
}

register_product( cpe:cpe, location:'ssh' );

log_message( data: build_detection_report( app:"Cisco UCS Director",
                                           version:rep_vers,
                                           install:"ssh",
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:0 );

exit(0);
