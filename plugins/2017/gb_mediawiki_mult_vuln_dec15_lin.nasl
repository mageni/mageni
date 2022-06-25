###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_dec15_lin.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# MediaWiki Multiple Vulnerabilities - Dec15 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108111");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2015-8622", "CVE-2015-8623", "CVE-2015-8624", "CVE-2015-8625",
                "CVE-2015-8626", "CVE-2015-8627", "CVE-2015-8628");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-29 07:49:40 +0200 (Wed, 29 Mar 2017)");
  script_name("MediaWiki Multiple Vulnerabilities - Dec15 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "os_detection.nasl", "secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-December/000186.html");

  script_tag(name:"summary", value:"This host is installed with MediaWiki
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to:

  - the (1) Special:MyPage, (2) Special:MyTalk, (3) Special:MyContributions, (4) Special:MyUploads, and (5) Special:AllMyUploads pages
  allow remote attackers to obtain sensitive user login information via crafted links combined with page view statistics.

  - not properly normalized IP addresses containing zero-padded octets, which might allow remote attackers to bypass intended access
  restrictions by using an IP address that was not supposed to have been allowed.

  - the User::randomPassword function generates passwords smaller than $wgMinimalPasswordLength, which makes it easier for remote
  attackers to obtain access via a brute-force attack.

  - not properly sanitized parameters when calling the cURL library, which allows remote attackers to read arbitrary files via an
  @ (at sign) character in unspecified POST array parameters.

  - the User::matchEditToken function in includes/User.php does not perform token comparison in constant time before determining if
  a debugging message should be logged, which allows remote attackers to guess the edit token and bypass CSRF protection via a timing attack,
  a different vulnerability than CVE-2015-8623.

  - the User::matchEditToken function in includes/User.php does not perform token comparison in constant time before returning, which
  allows remote attackers to guess the edit token and bypass CSRF protection via a timing attack, a different vulnerability than CVE-2015-8624.

  - Cross-site scripting (XSS) vulnerability, when is configured with a relative URL, allows remote authenticated users to inject arbitrary web
  script or HTML via wikitext, as demonstrated by a wikilink to a page named javascript:alert('XSS!').");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct XSS attacks, gain access to sensitive information and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.23.12, 1.24.x before 1.24.5, 1.25.x before 1.25.4, and 1.26.x before 1.26.1");

  script_tag(name:"solution", value:"Upgrade to version 1.23.12 or 1.24.5
  or 1.25.4 or 1.26.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mediawiki.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.23.12" ) ) {
  fix = "1.23.12";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.24.0", test_version2:"1.24.4" ) ) {
  fix = "1.24.5";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.25.0", test_version2:"1.25.3" ) ) {
  fix = "1.25.4";
  VULN = TRUE;
}

else if( version_is_equal( version:vers, test_version:"1.26.0" ) ) {
  fix = "1.26.1";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );