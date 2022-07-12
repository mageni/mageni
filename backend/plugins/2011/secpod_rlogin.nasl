###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rlogin.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# rlogin Passwordless / Unencrypted Cleartext Login
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901202");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-08-25 09:25:35 +0200 (Thu, 25 Aug 2011)");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0651");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("rlogin Passwordless / Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("find_service6.nasl");
  script_family("Useless services");
  script_require_ports("Services/rlogin", 513);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0651");
  script_xref(name:"URL", value:"http://en.wikipedia.org/wiki/Rlogin");
  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc1282.txt");

  script_tag(name:"summary", value:"This remote host is running a rlogin service.");

  script_tag(name:"insight", value:"rlogin has several serious security problems,

  - all information, including passwords, is transmitted unencrypted.

  - .rlogin (or .rhosts) file is easy to misuse (potentially allowing
  anyone to login without a password)");

  script_tag(name:"solution", value:"Disable the rlogin service and use alternatives like SSH instead.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

nullStr = raw_string( 0x00 );

## Client user name : Server user name : Terminal Type / Terminal Speed
req1 = "root" + nullStr + "root" + nullStr + "vt100/9600" + nullStr;

port = get_kb_item( "Services/rlogin" );
if( ! port ) port = 513;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_priv_sock_tcp( dport:port );
if( ! soc ) exit( 0 );

## Send Client Start-up flag
send( socket:soc, data:nullStr );

## Rlogin user info
send( socket:soc, data:req1 );

## Receive startup info flag
res1 = recv( socket:soc, length:1 );

## Receive data
res2 = recv( socket:soc, length:1024 );

close( soc );
if( isnull( res2 ) ) exit( 0 );

if( res1 == nullStr && "Password:" >< res2 ) {
  vuln = TRUE;
} else if( res1 == nullStr && ( ( "root@" >< res2 && ":~#" >< res2 ) || "Last login: " >< res2 || ( "Linux" >< res2 && " SMP" >< res2 ) ) ) {
  # TBD: Better matching patterns above?
  vuln = TRUE;
  report = "The service is misconfigured so it is allowing conntections without a password.";
}

if( vuln ) {
  security_message( port:port, data:report );
  set_kb_item( name:"rlogin/active", value:TRUE );
  register_service( port:port, proto:"rlogin", message:"A rlogin service seems to be running on this port." );
  exit( 0 );
}

exit( 99 );