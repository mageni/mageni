##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_iplanet_web_server_xss_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Oracle iPlanet Web Server Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:sun:iplanet_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902844");
  script_version("$Revision: 14117 $");
  script_bugtraq_id(53133);
  script_cve_id("CVE-2012-0516");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-29 16:16:16 +0530 (Fri, 29 Jun 2012)");
  script_name("Oracle iPlanet Web Server Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43942");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53133");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html");
  script_xref(name:"URL", value:"http://chingshiong.blogspot.in/2012/04/oracle-iplanet-web-server-709-multiple.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixSUNS");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
  script_require_ports("Services/www", 8989);
  script_mandatory_keys("java_system_web_server/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Oracle iPlanet WebServer 7.0");
  script_tag(name:"insight", value:"- Input passed via the 'helpLogoWidth' and 'helpLogoHeight' parameters to
    admingui/cchelp2/Masthead.jsp (when 'mastheadTitle' is set) and the
    'productNameSrc', 'productNameHeight', and 'productNameWidth' parameters
    to admingui/version/Masthead.jsp is not properly sanitised before being
    returned to the user.

  - Input passed via the 'appName' and 'pathPrefix' parameters to admingui/
    cchelp2/Navigator.jsp is not properly sanitised before being returned to
    the user.");
  script_tag(name:"solution", value:"Please see the referenced advisory for updates.");

  script_tag(name:"summary", value:"This host is running Oracle iPlanet Web Server and is prone to
  multiple cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_app_port(cpe:CPE);
if(! port){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)) {
  exit(0);
}

if(dir == "/") dir = "";

url = dir + "/admingui/version/Masthead.jsp?productNameSrc='%22--></style>" +
      "</script><script>alert(document.cookie)</script>&versionFile=../ver" +
      "sion/copyright?__token__=&productNameHeight=42&productNameWidth=221";

req = http_get(item:url, port:port);

res = http_keepalive_send_recv(port:port, data:req);

if(res && "<script>alert(document.cookie)</script>" >< res &&
   res =~ "HTTP/1.. 200" && "Server: Oracle-iPlanet-Web-Server" >< res){
  security_message(port:port);
  exit(0);
}

exit(99);