###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nfs_rpc_rquotad_service_detect.nasl 12057 2018-10-24 12:23:19Z cfischer $
#
# Nfs-utils rpc.rquotad Service Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802137");
  script_version("$Revision: 12057 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 14:23:19 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0625");
  script_name("Nfs-utils rpc.rquotad Service Detection");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap_tcp.nasl");
  script_require_keys("rpc/portmap");

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0625");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/265");
  script_xref(name:"URL", value:"http://www.exploitsearch.net/index.php?q=CVE-1999-0625");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/rquotad.htm");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute to gain
  information about NFS services including user/system quotas.");

  script_tag(name:"insight", value:"The flaw is due to error in the 'rpc.rquotad' service. If this
  service is running then disable it as it may become a security threat.");

  script_tag(name:"summary", value:"This script detects the running 'rpc.rquotad' service on the host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");

RPC_PROG = 100011;

port = get_rpc_port( program:RPC_PROG, protocol:IPPROTO_UDP );
if( port ) {
  security_message( port:port, proto:"udp" );
}

port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP );
if( port ) {
  security_message( port:port, proto:"tcp" );
}

exit( 0 );
