###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_edirectory_detect.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Novell/NetIQ eDirectory Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100339");
  script_version("$Revision: 12413 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-11-06 12:41:10 +0100 (Fri, 06 Nov 2009)");
  script_name("Novell/NetIQ eDirectory Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"Detection of Novell/NetIQ eDirectory.

  This script performs LDAP based detection of Novell/NetIQ eDirectory");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");

include("host_details.inc");
include("ldap.inc");

port = get_ldap_port( default:389 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

req = raw_string(
                  0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,
                  0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,
                  0x43,0x6c,0x61,0x73,0x73,0x30,0x00
                );

if( ! res = ldap_send_recv( req:req, sock:soc ) )
{
  close( soc );
  exit( 0 );
}

close( soc );

str = bin2string( ddata:res, noprint_replacement:"#" );

if( str !~ "LDAP Agent for (Novell|NetIQ) eDirectory" && "Anonymous Simple Bind Disabled" >!< str )
  exit( 0 );

version = 'unknown';

set_kb_item( name:"eDirectory/installed", value:TRUE );

# LDAP Agent for NetIQ  eDirectory 9.0 (40002.38)
# LDAP Agent for Novell eDirectory 8.8 SP5 Patch 4 (20504.13)
# LDAP Agent for Novell eDirectory 8.8 SP2 (20216.46)
v = eregmatch( pattern:'LDAP Agent for (Novell|NetIQ) eDirectory (([0-9.]+)( SP([0-9]+))?( Patch ([0-9]+))?( \\(([^)]+)\\)))', string:str );

report_version = "unknown";

product = 'Novell';

if( ! isnull( v[1] ) )
  product = v[1];

if( product == "Novell" )
  cpe = 'cpe:/a:novell:edirectory';
else
  cpe = 'cpe:/a:netiq:edirectory';

if( ! isnull( v[3] ) )
{
  version = v[3];
  cpe += ':' + version;
  set_kb_item( name:"ldap/eDirectory/" + port + "/version", value:version );
  report_version += version;
}

if( ! isnull( v[5] ) )
{
  sp = v[5];
  set_kb_item( name:"ldap/eDirectory/" + port + "/sp", value:sp );
  report_version += " SP" + sp;
}

if( ! isnull( v[7] ) )
{
  patch = v[7];
  set_kb_item( name:"ldap/eDirectory/" + port + "/patch", value:patch );
  report_version += " Patch" + patch;
}

if( ! isnull( v[9] ) )
{
  build = v[9];
  set_kb_item( name:"ldap/eDirectory/" + port + "/build", value:build );
  report_version += " (" + build + ")";
}

register_product( cpe:cpe, location:port + '/tcp', port:port, service:"ldap" );

report = build_detection_report( app:product + " eDirectory", version:report_version, install:port + '/tcp', cpe:cpe, concluded:v[0] );

log_message( port:port, data:report );

exit( 0 );
