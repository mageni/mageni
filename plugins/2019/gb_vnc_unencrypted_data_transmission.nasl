###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vnc_unencrypted_data_transmission.nasl 13014 2019-01-10 09:55:42Z cfischer $
#
# VNC Server Unencrypted Data Transmission
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.108529");
  script_version("$Revision: 13014 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-10 10:55:42 +0100 (Thu, 10 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-10 09:23:25 +0100 (Thu, 10 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_name("VNC Server Unencrypted Data Transmission");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("vnc_security_types.nasl");
  script_require_ports("Services/vnc", 5900, 5901, 5902);
  script_mandatory_keys("vnc/security_types/detected");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc6143#page-10");

  script_tag(name:"summary", value:"The remote host is running a VNC server providing one or more insecure or
  cryptographically weak Security Type(s) not intended for use on untrusted networks.");

  script_tag(name:"impact", value:"An attacker can uncover sensitive data by sniffing traffic to the
  VNC server.");

  script_tag(name:"solution", value:"Run the session over an encrypted channel provided by IPsec [RFC4301] or SSH [RFC4254].
  Some VNC server vendors are also providing more secure Security Types within their products.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");

# https://tools.ietf.org/html/rfc6143#page-10
# TODO: Find more security_types transferring data unencrypted
check_types = make_array( 1, "None",
                          2, "VNC authentication" );

report = 'The VNC server provides the following insecure or cryptographically weak Security Type(s):\n';

port = get_kb_item( "Services/vnc" );
if( ! port )
  port = 5900;

if( ! get_port_state( port ) )
  exit( 0 );

# Just to be sure...
encaps = get_port_transport( port );
if( encaps > ENCAPS_IP )
  exit( 99 );

if( ! security_types = get_kb_list( "vnc/" + port + "/security_types" ) )
  exit( 0 );

foreach security_type( security_types ) {
  if( array_key_exist( key:security_type, array:check_types, part_match:FALSE ) ) {
    report += '\n' + security_type + " (" + check_types[int( security_type ) ] + ")";
    VULN = TRUE;
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );