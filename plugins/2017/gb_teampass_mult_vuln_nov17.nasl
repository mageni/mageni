###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teampass_mult_vuln_nov17.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# TeamPass Multiple Vulnerabilities - Nov17
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

CPE = 'cpe:/a:teampass:teampass';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112142");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-15051", "CVE-2017-15052", "CVE-2017-15053", "CVE-2017-15054", "CVE-2017-15055", "CVE-2017-15278");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-28 08:41:00 +0100 (Tue, 28 Nov 2017)");
  script_name("TeamPass Multiple Vulnerabilities - Nov17");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("teampass/installed");

  script_xref(name:"URL", value:"http://blog.amossys.fr/teampass-multiple-cve-01.html");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/releases/tag/2.1.27.9");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/blob/master/changelog.md");

  script_tag(name:"summary", value:"This host is installed with TeamPass and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple stored cross-site scripting (XSS) vulnerabilities via the (1) URL value of an item or (2) user log history. (CVE-2017-15051)

  - No proper access control on users.queries.php. (CVE-2017-15052)

  - No proper access control on roles.queries.php. (CVE-2017-15053)

  - Arbitrary file upload. (CVE-2017-15054)

  - No proper access control on items.queries.php. (CVE-2017-15055)

  - Cross-Site Scripting (XSS) due to insufficient filtration of data (in /sources/folders.queries.php). (CVE-2017-15278)");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site, upload malicious code as an authenticated user or modify/delete any arbitrary roles within the application.");

  script_tag(name:"affected", value:"TeamPass version 2.1.27.8 and prior.");

  script_tag(name:"solution", value:"Upgrade to TeamPass 2.1.27.9 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://teampass.net/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.1.27.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.27.9" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
