###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetty_shared_buffers_info_leak_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# Jetty Shared Buffers Information Leakage Vulnerability
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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805051");
  script_cve_id("CVE-2015-2080");
  script_version("$Revision: 11452 $");
  script_bugtraq_id(72768);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-02 14:50:23 +0530 (Mon, 02 Mar 2015)");

  script_name("Jetty Shared Buffers Information Leakage Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Jetty webserver and is prone to information
leakage vulnerability.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");

  script_tag(name:"insight", value:"The flaw is triggered when handling 400 errors in HTTP responses. This may
allow a remote attacker to gain access to potentially sensitive information in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to  obtain sensitive
information that may aid in further attacks.");

  script_tag(name:"affected", value:"Jetty versions 9.2.3 to 9.2.8 and beta releases of 9.3.x");


  script_tag(name:"solution", value:"Upgrade to Jetty 9.2.9.v20150224 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/12");
  script_xref(name:"URL", value:"http://dev.eclipse.org/mhonarc/lists/jetty-announce/msg00075.html");
  script_xref(name:"URL", value:"http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl");
  script_mandatory_keys("Jetty/installed");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("host_details.inc");
include("http_func.inc");


if (!http_port = get_app_port(cpe: CPE))
  exit(0);

host = get_host_name();
if( http_port != 80 && http_port != 443 )
  host += ':' + http_port;

sndReq =  string("POST / HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Referer: ", raw_string(0x00), "\r\n",
                 "Content-Length: 0\r\n\r\n");
rcvRes = http_send_recv(port:http_port, data:sndReq);

if(rcvRes && rcvRes =~ "HTTP/1.. 400" && "Illegal character 0x0 in state=HEADER_VALUE" >< rcvRes) {
  security_message(port:http_port);
  exit(0);
}

exit(99);
