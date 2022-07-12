###############################################################################
# OpenVAS Vulnerability Test
# $Id: SHN_discard.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Check for Discard Service
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2003 StrongHoldNet
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11367");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0636");
  script_name("Check for Discard Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 StrongHoldNet");
  script_family("Useless services");
  script_dependencies("find_service.nasl");
  script_require_ports(9);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0636");

  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'discard' line in /etc/inetd.conf
  and restart the inetd process

  - Under Windows systems, set the following registry key to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpDiscard

  Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp

  To restart the service.");

  script_tag(name:"summary", value:"The remote host is running a 'discard' service. This service
  typically sets up a listening socket and will ignore all the data which it receives.

  This service is unused these days, so it is advised that you disable it.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = 9; # Discard is not supposed to run on any other port.
if( ! service_is_unknown( port:port ) ) exit( 0 );

# We send between 17 and 210 bytes of random data.
# If the service is still listening without any output, we assume
# that 9/tcp is running 'discard'.
function check_discard( soc ) {

  local_var n, res;
  if( ! soc ) return( 0 );

  n = send( socket:soc, data:string( crap( length:(rand()%193+17), data:string(rand())),"\r\n\r\n" ) );
  if( n < 0 ) return( 0 );

  res = recv( socket:soc, length:1024, timeout:5 );
  if( strlen( res ) > 0 ) return( 0 );

  return( 1 );
}

if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( check_discard( soc ) ) {
    security_message( port:port );
    register_service( port:port, proto:"discard" );
    if( soc ) close( soc );
    exit( 0 );
  }
}

exit( 99 );