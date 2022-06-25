###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_file_upload_vuln.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Tiki Wiki CMS Groupware File Upload Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106131");
  script_version("$Revision: 12083 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-13 13:02:15 +0700 (Wed, 13 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Tiki Wiki CMS Groupware File Upload Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"https://tiki.org/article434-Security-update-Tiki-15-2-Tiki-14-4-and-Tiki-12-9-released");
  script_xref(name:"URL", value:"https://www.mehmetince.net/exploit/tiki-wiki-unauthenticated-file-upload-vulnerability");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a remote file upload vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version and components is/are present on the target host.");

  script_tag(name:"insight", value:"The 3rd party component ELFinder 2.0 comes with an example page which
  demonstrates file upload, remove, rename and creating directories. The default configuration of Tiki Wiki
  CMS Groupware does not enforce validation on file extensions, etc.");

  script_tag(name:"impact", value:"An unauthenticated attacker may upload PHP files and execute them.");

  script_tag(name:"affected", value:"Versions 15.1, 14.3 and 12.8 LTS and prior.");

  script_tag(name:"solution", value:"Update to the latest supported version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );

ver = infos['version'];
dir = infos['location'];

if( version_is_less( version:ver, test_version:"12.9" ) ||
    version_in_range( version:ver, test_version:"14.0", test_version2:"14.3" ) ||
    version_in_range( version:ver, test_version:"15.0", test_version2:"15.1" ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/vendor_extra/elfinder/elfinder.html";

  if( http_vuln_check( port:port, url:url, pattern:"<title>elFinder 2.0</title>",
                       check_header:TRUE, extra_check:"php/connector.minimal.php" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
