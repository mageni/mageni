##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cmscout_xss_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# CMScout Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800791");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2154");
  script_bugtraq_id(40442);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CMScout Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39986");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58996");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12806/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1288");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cmscout_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("CMScout/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  script code.");

  script_tag(name:"affected", value:"CMScout version 2.09 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the 'search'
  module when processing the 'search' parameter in 'index.php' page.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running CMScout and is prone to Cross Site
  Scripting Vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cmsPort = get_http_port(default:80);
cmsVer = get_kb_item("www/" + cmsPort + "/CMScout");
if(!cmsVer){
  exit(0);
}

cmsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:cmsVer);
if(cmsVer[2] != NULL)
{

  if(cmsVer[2] == "/")
    cmsVer[2] = "";

  filename = string(cmsVer[2] + "/index.php?page=search&menuid=5");
  useragent = http_get_user_agent();
  authVariables = "search=VT+XSS+Testing&content=1&Submit=Search";

  host = http_host_name(port:cmsPort);

  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", useragent, "\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us,en;q=0.5\r\n",
                   "Accept-Encoding: gzip,deflate\r\n",
                   "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                   "Keep-Alive: 300\r\n",
                   "Connection: keep-alive\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Cookie: cmscout2=1f9f3e24745df5907a131c9acb41e5ef\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);
  rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

  if("(VT XSS Testing)" >< rcvRes){
    report = report_vuln_url(port:cmsPort, url:filename);
    security_message(port:cmsPort, data:report);
  }
}
