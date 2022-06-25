##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_unified_commu_manager_mult_vuln.nasl 14184 2019-03-14 13:29:04Z cfischer $
#
# Cisco Unified Communications Manager Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805097");
  script_version("$Revision: 14184 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:29:04 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-24 17:37:08 +0530 (Mon, 24 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Cisco Unified Communications Manager Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Cisco Unified
  Communications Manager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  and check whether it is able to execute the code");

  script_tag(name:"insight", value:"The flaws are due to,

  - Authenticated users of CUCM can access limited functionality via the web
  interface and Cisco console (SSH on port 22). Because the SSH server is
  configured to process several environment variables from the client and a
  vulnerable version of bash is used, it is possible to exploit command
  injection via specially crafted environment variables.

  - The application allows users to view the contents of any locally accessible
  files on the web server through a vulnerability known as LFI (Local File Inclusion).

  - The pingExecute servlet allows unauthenticated users to execute pings to
  arbitrary IP addresses. This could be used by an attacker to enumerate the
  internal network.

  - Authentication for some methods in the EPAS SOAP interface can be bypassed
  by using a hardcoded session ID. The methods 'GetUserLoginInfoHandler' and
  'GetLoggedinXMPPUserHandler' are affected.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to spawn a shell running as the user 'admin', enumerate the internal
  network, view the contents of any locally accessible files on the web server.");

  script_tag(name:"affected", value:"Cisco Unified Communications Manager 9.x < 9.2,
  10.x < 10.5.2, 11.x < 11.0.1.");

  script_tag(name:"solution", value:"Upgrade to CUCM version 9.2, 10.5.2 or
  11.0.1 pr later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37816/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_unified_commu_manager_detect.nasl");
  script_mandatory_keys("Cisco/CUCM/Installed");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/pingExecute?hostname=10.0.0.1&interval=1.0" +
     "&packetsize=12&count=1000&secure=false";

sndReq = http_get(item:url, port:http_port);
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

if("PING" >< rcvRes && "bytes of data" >< rcvRes && "bytes from" >< rcvRes
   && "icmp_seq" >< rcvRes &&  "time=" >< rcvRes)
{
  security_message(port:http_port);
  exit(0);
}

exit(99);