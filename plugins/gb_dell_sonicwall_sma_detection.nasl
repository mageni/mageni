###############################################################################
# OpenVAS Vulnerability Test
#
# Dell SonicWALL Secure Mobile Access / Secure Remote Access Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107118");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-09 13:26:09 +0700 (Mon, 09 Jan 2017)");
  script_name("Dell SonicWALL Secure Mobile Access / Secure Remote Access Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Dell SonicWALL Secure Mobile Access (SMA)
  and Secure Remote Access (SRA).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("cpe.inc");
include("snmp_func.inc");

port    = get_snmp_port( default:161 );
sysdesc = get_snmp_sysdesc( port:port );
if( ! sysdesc ) exit( 0 );

if( sysdesc !~ 'Dell SonicWALL S[R|M]A' ) exit( 0 );
Pro = eregmatch( pattern: 'Dell SonicWALL ([A-Z]+)', string:sysdesc );
if ( ! isnull( Pro[1] ) )
{
  Product = Pro[1];
}

set_kb_item( name:"sonicwall/" + tolower( Product ) + "/detected", value:TRUE );


vers = "unknown";
series = "unknown";
if( sysdesc =~ 'Dell SonicWALL S[R|M]A Virtual Appliance' )
{
  version = eregmatch( string:sysdesc, pattern:'Dell SonicWALL S[R|M]A Virtual Appliance [(]SonicOS SSL[-]VPN (([0-9.]+)[-][0-9]{2}sv)', icase:TRUE );
  if( ! isnull( version[1] ) ) vers = chomp( version[1] );
}
else
{
  version = eregmatch( string:sysdesc, pattern:'Dell SonicWALL S[M|R]A ([0-9a-zA-Z]+) [(].*\\s(([0-9.]+)[-][0-9]{2}sv)[)]', icase:TRUE );

  if( ! isnull( version[2] ) ) vers = chomp( version[2] );

  if( ! isnull( version[1] ) ) series = version[1];
}
if ( Product == "SMA" )
{
  cpe = build_cpe( value:vers, exp:"^([0-9.]+[-][0-9]{2}sv)", base:"cpe:/o:dell:sonicwall_secure_mobile_access:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/o:dell:sonicwall_secure_mobile_access';

}
else if ( Product == "SRA" )
{
  cpe = build_cpe( value:vers, exp:"^([0-9.]+[-][0-9]{2}sv)", base:"cpe:/o:dell:sonicwall_secure_remote_access_firmware:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/o:dell:sonicwall_secure_remote_access_firmware:';

}
if ( ! isnull(series)) set_kb_item( name:'sonicwall/' + tolower( Product ) + '/series', value:series );
if ( ! isnull(vers)) set_kb_item( name:'sonicwall/' + tolower( Product ) + '/version', value:vers );

register_product( cpe:cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp" );
log_message( data:build_detection_report( app:"Dell SonicWALL " + Product,
                                          version:vers,
                                          install:port + "/udp",
                                          cpe:cpe,
                                          concluded:sysdesc ),
                                          port:port,
                                          proto:"udp" );

exit( 0 );

