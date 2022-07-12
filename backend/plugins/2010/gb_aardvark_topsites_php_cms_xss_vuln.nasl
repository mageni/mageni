###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aardvark_topsites_php_cms_xss_vuln.nasl 11396 2018-09-14 16:36:30Z cfischer $
#
# Aardvark Topsites PHP 'index.php' Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801556");
  script_version("$Revision: 11396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 18:36:30 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-4097");
  script_bugtraq_id(44390);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Aardvark Topsites PHP 'index.php' Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/514423/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Aardvark Topsites PHP version 5.2 and 5.2.1");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input via the 'mail', 'title', 'u', and 'url' parameters to 'index.php' that
  allows the attackers to execute arbitrary HTML and script code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Aardvark Topsites PHP CMS and is prone to cross
  site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach path( make_list( "/atsphp", "/" ) ) {

  if( path == "/" ) path = "";

  res = http_get_cache(item:path + "/index.php", port:port);

  if(">Aardvark Topsites PHP<" >< res) {

    url = path + '/index.php?a=search&q="onmouseover=alert("XSS-TEST") par="';
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && 'onmouseover=alert("XSS-TEST")" />' >< res) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);