###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ise_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Identity Services Engine Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105469");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-01 13:44:48 +0100 (Tue, 01 Dec 2015)");
  script_name("Cisco Identity Services Engine Detection");

  script_tag(name:"summary", value:"This script performs ssh based detection of Cisco Identity Services Engine");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_ise/show_ver");
  exit(0);
}


include("host_details.inc");

show_ver = get_kb_item("cisco_ise/show_ver");

if( ! show_ver || "Cisco Identity Services Engine" >!< show_ver ) exit( 0 );

cpe = 'cpe:/a:cisco:identity_services_engine';
vers = 'unknown';

sv = split( show_ver, keep:FALSE );
x = 0;

foreach line ( sv )
{
  x++;
  if( "Cisco Identity Services Engine" >< line && "Patch" >!< line && sv[x] =~ '^--------' )
  {
    version = eregmatch( pattern:'[^ ]*Version\\s*:\\s*([0-9]+[^\r\n]+)', string:sv[ x+1 ] ); # e.g.: 1.1.4.218
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      set_kb_item( name:'cisco_ise/version', value:vers );
      cpe += ':' + vers;
    }
  }

  if( "Cisco Identity Services Engine Patch" >< line && sv[x] =~ '^--------' )
  {
    p_version = eregmatch( pattern:'[^ ]*Version\\s*:\\s*([0-9]+[^\r\n]+)', string:sv[ x+1 ] ); # e.g.: 13
    if( ! isnull( p_version[1] ) )
    {
      patch = p_version[1];
      set_kb_item( name:'cisco_ise/patch', value:patch );
    }
  }
}

if( ! patch ) set_kb_item( name:"cisco_ise/patch", value:"0" );

register_product( cpe:cpe, location:'ssh' );

log_message( data: build_detection_report( app:'Cisco Identity Services Engine',
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: 'show version' ),
             port:0 );

exit( 0 );
