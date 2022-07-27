###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_aug12_win.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# MediaWiki Multiple Vulnerabilities - Aug12 (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112114");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2012-4377", "CVE-2012-4378", "CVE-2012-4379", "CVE-2012-4380", "CVE-2012-4382");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-08 13:58:17 +0100 (Wed, 08 Nov 2017)");
  script_name("MediaWiki Multiple Vulnerabilities - Aug12 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "os_detection.nasl", "secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"This host is installed with MediaWiki
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to:

  - a Cross-site scripting (XSS) vulnerability that allows remote attackers to inject arbitrary web script or HTML via a File: link to a nonexistent image.

  - multiple cross-site scripting (XSS) vulnerabilities, when unspecified JavaScript gadgets are used, allow remote attackers
  to inject arbitrary web script or HTML via the userlang parameter to w/index.php.

  - MediaWiki not sending a restrictive X-Frame-Options HTTP header, which allows remote attackers to conduct clickjacking attacks via an embedded API response in an IFRAME element.

  - MediaWiki allowing remote attackers to bypass GlobalBlocking extension IP address blocking and thus creating an account via unspecified vectors.

  - MediaWiki not properly protecting user block metadata, which allows remote administrators to read a user block reason via a reblock attempt.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct XSS attacks, affect the application's integrity and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.18.5, and 1.19.x before 1.19.2");

  script_tag(name:"solution", value:"Upgrade to version 1.18.5 or 1.19.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.mediawiki.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.18.5" ) ) {
  fix = "1.18.5";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.19.0", test_version2:"1.19.1" ) ) {
  fix = "1.19.2";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
