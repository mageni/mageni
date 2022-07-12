##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_uselang_param_xss_vuln.nasl 11818 2018-10-10 11:35:42Z asteins $
#
# MediaWiki 'uselang' Parameter Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802910");
  script_version("$Revision: 11818 $");
  script_cve_id("CVE-2012-2698");
  script_bugtraq_id(53998);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 13:35:42 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 13:41:49 +0530 (Mon, 09 Jul 2012)");
  script_name("MediaWiki 'uselang' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49484");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027179");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76311");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=36938");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/06/14/2");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"MediaWiki versions prior to 1.17.5, 1.8.x before 1.18.4 and 1.19.x before 1.19.1");
  script_tag(name:"insight", value:"Input passed via the 'uselang' parameter to 'index.php/Main_page' is not
  properly sanitised in the 'outputPage()' function, before being returned
  to the user.");
  script_tag(name:"solution", value:"Upgrade to MediaWiki version 1.17.5, 1.18.4, or 1.19.1 or later.");
  script_tag(name:"summary", value:"This host is running MediaWiki and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mediawiki.org/wiki/MediaWiki");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");


if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)){
  exit(0);
}

host = http_host_name(port:port);

url = dir + '/index.php/Main_Page?uselang=a%27%20onmouseover=eval(alert("document.cookie"))%20e=%27';
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);

if(egrep(pattern:"^HTTP/.* 200 OK", string:res) &&
         'alert("document.cookie")' >< res && ">MediaWiki" >< res){
  security_message(port:port);
}
