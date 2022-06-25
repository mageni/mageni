###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortigate_zebos_shell_cve_2015_7361.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# FortiGate: ZebOS routing remote shell service enabled
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140112");
  script_version("$Revision: 11874 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2015-7361");

  script_name("FortiGate: ZebOS routing remote shell service enabled");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-15-020");

  script_tag(name:"vuldetect", value:"Open a connection to port 2650 and execute the `show version` command.");
  script_tag(name:"insight", value:"A remote attacker may access the internal ZebOS shell of FortiOS 5.2.3 without authentication on the HA dedicated management interface only.

Only FortiGates configured with HA *and* with an enabled HA dedicated management interface are vulnerable.");

  script_tag(name:"solution", value:"FortiOS 5.2.3 must be upgraded to FortiOS 5.2.4.");
  script_tag(name:"summary", value:"ZebOS routing remote shell service enabled");
  script_tag(name:"affected", value:"FortiGate v5.2.3 only.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-02 12:27:55 +0100 (Mon, 02 Jan 2017)");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/zebos_routing_shell");

  exit(0);
}

include("misc_func.inc");

if( ! port = get_kb_item("Services/zebos_routing_shell") ) exit( 0 );

if( ! get_port_state( port ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 99 );

recv = recv( socket:soc, length:128 );

if( "ZebOS" >!< recv )
{
  close( soc );
  exit( 99 );
}

send( socket:soc, data:'show version\n' );
recv = recv( socket:soc, length:512 );

close( soc );

if( "ZebOS version" >< recv && "IP Infusion Inc" >< recv )
{
  report = 'The ZebOS routing remote shell is accessible at this port without authentication. Running "show version" gives the following output:\n' + recv + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

