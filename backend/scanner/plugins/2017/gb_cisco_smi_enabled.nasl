###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_smi_enabled.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Cisco Smart Install Protocol Misuse
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140162");
  script_version("$Revision: 13541 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-02-16 11:39:34 +0100 (Thu, 16 Feb 2017)");
  script_name("Cisco Smart Install Protocol Misuse");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("find_service.nasl");
  script_require_ports(4786);

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20170214-smi");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/540130");
  script_xref(name:"URL", value:"https://2016.zeronights.ru/wp-content/uploads/2016/12/CiscoSmartInstall.v3.pdf");
  script_xref(name:"URL", value:"http://www.cisco.com/c/en/us/td/docs/switches/lan/smart_install/configuration/guide/smart_install/concepts.html#23355");

  script_tag(name:"summary", value:"Several researchers have reported on the use of Smart Install (SMI) protocol messages toward Smart Install clients,
  also known as integrated branch clients (IBC), allowing an unauthenticated, remote attacker to change the startup-config file and force a reload of the
  device, load a new IOS image on the device, and execute high-privilege CLI commands on switches running Cisco IOS and IOS XE Software.

  Cisco does not consider this a vulnerability in Cisco IOS, IOS XE, or the Smart Install feature itself but a misuse of the Smart Install protocol, which
  does not require authentication by design. Customers who are seeking more than zero-touch deployment should consider deploying the Cisco Network Plug and
  Play solution instead.");

  script_tag(name:"solution", value:"Cisco has updated the Smart Install Configuration Guide to include security best practices regarding the deployment of
  the Cisco Smart Install feature within customer infrastructures.");

  # it seems we are not able to distinguish between Director and Client. As director is not affected,
  # use a lower QOd but high enough so it's shown by default.
  script_tag(name:"qod", value:"75");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = 4786;

if( ! get_port_state( port ) ) exit( 0 );
if( ! soc = open_sock_tcp( port ) ) exit( 0 );

req =  raw_string( 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
                   0x00
                 );

send( socket:soc, data:req );
recv = recv( socket:soc, length:20, timeout:30 );
close( soc );

if( ! recv || strlen( recv ) != 20 ) exit( 0 );

if( hexstr( recv ) =~ "^0000000400000000000000040000000400000001$" )
{
  register_service( port:port, proto:"cisco_smi" );
  security_message( port:port );
  exit( 0 );
}

exit( 99 );