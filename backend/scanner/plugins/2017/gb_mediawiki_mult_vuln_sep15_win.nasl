###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_sep15_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# MediaWiki Multiple Vulnerabilities - Sep15 (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108091");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2015-6727", "CVE-2015-6728", "CVE-2015-6729", "CVE-2015-6730", "CVE-2013-7444");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-09 10:45:17 +0100 (Thu, 09 Mar 2017)");
  script_name("MediaWiki Multiple Vulnerabilities - Sep15 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "os_detection.nasl", "secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"This host is installed with MediaWiki
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to:

  - the Special:DeletedContributions page allows remote attackers to determine if an IP is autoblocked via the 'Change block' text.

  - the ApiBase::getWatchlistUser function does not perform token comparison in constant time,
  which allows remote attackers to guess the watchlist token and bypass CSRF protection via a timing attack.

  - Cross-site scripting (XSS) vulnerability in thumb.php via the rel404 parameter, which is not properly handled in an error page.

  - Cross-site scripting (XSS) vulnerability in thumb.php via the f parameter, which is not properly handled in an error page, related to 'ForeignAPI images.'");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct XSS attacks, gain access to sensitive information and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.23.10, 1.24.x before 1.24.3,
  and 1.25.x before 1.25.2");

  script_tag(name:"solution", value:"Upgrade to version 1.23.10 or 1.24.3
  or 1.25.2 or later.");
  script_xref(name:"URL", value:"http://www.mediawiki.org");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.23.10" ) ) {
  fix = "1.23.10";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.24.0", test_version2:"1.24.2" ) ) {
  fix = "1.24.3";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.25.0", test_version2:"1.25.1" ) ) {
  fix = "1.25.2";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
