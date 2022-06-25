###############################################################################
# OpenVAS Vulnerability Test
# $Id: cubecart_lang_xss.nasl 12159 2018-10-30 04:28:13Z ckuersteiner $
#
# Brooky CubeCart index.php language XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

# Ref: John Cobb

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17227");
  script_version("$Revision: 12159 $");
  script_bugtraq_id(12549);
  script_cve_id("CVE-2005-0442", "CVE-2005-0443");
  script_tag(name:"last_modification", value:"$Date: 2018-10-30 05:28:13 +0100 (Tue, 30 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Brooky CubeCart index.php language XSS");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_tag(name:"summary", value:"The version of CubeCart is vulnerable to cross-site scripting and remote script
  injection due to a lack of sanitization of user-supplied data.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to execute
  malicious script code on a vulnerable server.");

  script_tag(name:"solution", value:"Upgrade to version 2.0.5 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
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

  url = string( dir, "/upload/index.php?&language=<script>", vtstrings["lowercase"], "-xss-test</script>" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<script>" + vtstrings["lowercase"] + "-xss-test</script>", string:res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

ver = infos['version'];
if( ! ver )
  exit( 0 );

if( version_is_less_equal( version:ver, test_version:"2.0.4" ) ){
  report = report_fixed_ver( installed_version:ver, fixed_version:"2.0.5" );
  security_message( port:port, data:report );
}

exit( 0 );
