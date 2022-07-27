###############################################################################
# OpenVAS Vulnerability Test
# $Id: auth_enabled.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Check for ident Service
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
  script_oid("1.3.6.1.4.1.25623.1.0.100081");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0629");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Check for ident Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/auth", 113);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0629");

  script_tag(name:"summary", value:"The remote host is running an ident daemon.

  The Ident Protocol is designed to work as a server daemon, on a user's
  computer, where it receives requests to a specified port, generally 113. The
  server will then send a specially designed response that identifies the
  username of the current user.");
  script_tag(name:"impact", value:"The ident protocol is considered dangerous because it allows hackers to gain
  a list of usernames on a computer system which can later be used for attacks.");
  script_tag(name:"solution", value:"Disable the ident Service.");
  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item( "Services/auth" );
if( ! port ) port = 113;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

data = strcat( port, ',', get_source_port( soc ) );
send( socket:soc, data:string( data, "\r\n" ) );
buf = recv_line( socket:soc, length:1024 );

close( soc );

if( "ERROR" >< buf || data >< buf || "USERID" >< buf ) {
  security_message( port:port );
  register_service( port:port, proto:"auth" );
  exit( 0 );
}

exit( 99 );
