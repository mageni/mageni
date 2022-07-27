###############################################################################
# OpenVAS Vulnerability Test
# $Id: rexecd.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# rexec Passwordless / Unencrypted Cleartext Login
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
  script_oid("1.3.6.1.4.1.25623.1.0.100111");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-08 12:09:59 +0200 (Wed, 08 Apr 2009)");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0618");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("rexec Passwordless / Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("find_service6.nasl");
  script_require_ports("Services/rexec", 512);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0618");

  script_tag(name:"summary", value:"This remote host is running a rexec service.");

  script_tag(name:"insight", value:"rexec (Remote Process Execution) has the same kind of functionality
  that rsh has: you can execute shell commands on a remote computer.

  The main difference is that rexec authenticate by reading the
  username and password *unencrypted* from the socket.");

  script_tag(name:"solution", value:"Disable the rexec service and use alternatives like SSH instead.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

# sending a too long username. Without that too long username i did
# not get any response from rexecd.
for( i = 0; i < 260; i++ ) {
  username += string("x");
}

rexecd_string = string( raw_string( 0 ), username, raw_string( 0 ), "xxx", raw_string( 0 ), "id", raw_string( 0 ) );

port = get_kb_item( "Services/rexec" );
if( ! port ) port = 512;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:rexecd_string );
buf = recv_line( socket:soc, length:4096 );
close( soc );
if( isnull( buf ) ) exit( 0 );

# TBD: ord( buf[0] ) == 1 || was previously tested here but
# that is to prone for false positives against all unknown ports...
if( "too long" >< buf || "Where are you?" >< buf ) {
  register_service( port:port, proto:"rexec", message:"A rexec service seems to be running on this port." );
  if( "Where are you?" >< buf ) {
    report = "The rexec service is not allowing connections from this host.";
  }
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );