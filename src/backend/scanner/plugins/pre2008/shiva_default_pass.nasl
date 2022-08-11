###############################################################################
# OpenVAS Vulnerability Test
# $Id: shiva_default_pass.nasl 13634 2019-02-13 12:06:16Z cfischer $
#
# Shiva Integrator Default Password
#
# Authors:
# Stefaan Van Dooren <stefaanv@kompas.be>
#
# Copyright:
# Copyright (C) 2000 Stefaan Van Dooren
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
  script_oid("1.3.6.1.4.1.25623.1.0.10500");
  script_version("$Revision: 13634 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 13:06:16 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0508");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Shiva Integrator Default Password");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Stefaan Van Dooren");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"solution", value:"Telnet to this router and set a different password immediately.");

  script_tag(name:"summary", value:"The remote Shiva router uses the default password.
  This means that anyone who has (downloaded) a user manual can
  telnet to it and reconfigure it to lock you out of it, and to
  prevent you to use your internet connection.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

data = string( "hello\n\r" );
send( data:data, socket:soc );
buf = recv( socket:soc, length:4096 );

close( soc );

if( "ntering privileged mode" >< buf ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );