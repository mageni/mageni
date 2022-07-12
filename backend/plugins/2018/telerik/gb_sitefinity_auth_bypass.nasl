###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitefinity_auth_bypass.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Sitefinity Authentication Bypass Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113078");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-10 14:49:50 +0100 (Wed, 10 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15883");

  script_name("Sitefinity Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sitefinity_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sitefinity/detected");

  script_tag(name:"summary", value:"Sitefinity allows remote attackers to bypass authentication.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to weak cryptography.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain privileges or cause a denial of service on load balanced sites.");
  script_tag(name:"affected", value:"Sitefinity versions 5.1, 5.2, 5.3, 5.4, 6.x, 7.x, 8.x, 9.x, 10.x");
  script_tag(name:"solution", value:"Depending on the currently installed version, update Sitefinity to version 5.1.3460.0, 5.2.3810.0., 5.3.3930.0, 5.4.4050.0, 6.0.4220.0, 6.1.4710.0, 6.2.4920.0, 6.3.5040.0, 7.0.5130.0, 7.1.5230.0, 7.2.5340.0, 7.3.5680.0, 8.0.5760.0, 8.1.5840.0, 8.2.5950.0, 9.0.6040.0, 9.1.6160.0, 10.0.6413.0, 10.1.6504.0 respectively.");

  script_xref(name:"URL", value:"https://knowledgebase.progress.com/articles/Article/Sitefinity-Security-Advisory-for-cryptographic-vulnerability-CVE-2017-15883");
  script_xref(name:"URL", value:"https://www.mnemonic.no/news/2017/vulnerability-finding-sitefinity-cms/");

  exit(0);
}

CPE = "cpe:/a:progress:sitefinity";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.1.0.0", test_version2: "5.1.3459.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.3460.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.2.0.0", test_version2: "5.2.3809.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.3810.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.3.0.0", test_version2: "5.3.3929.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3.3930.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.4.0.0", test_version2: "5.4.4049.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.4.4050.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0.0", test_version2: "6.0.4219.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.4220.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.1.0.0", test_version2: "6.1.4709.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.1.4710.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.2.0.0", test_version2: "6.2.4919.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.2.4920.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.3.0.0", test_version2: "6.3.5039.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3.5040.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.0.0.0", test_version2: "7.0.5129.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.5130.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.1.0.0", test_version2: "7.1.5229.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1.5230.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.2.0.0", test_version2: "7.2.5339.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.5340.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.3.0.0", test_version2: "7.3.5679.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.5680.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.0.0.0", test_version2: "8.0.5759.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.5760.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.1.0.0", test_version2: "8.1.5839.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.1.5840.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.2.0.0", test_version2: "8.2.5949.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.5950.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.0.0.0", test_version2: "9.0.6039.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0.6040.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.1.0.0", test_version2: "9.1.6159.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.1.6160.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.2.0.0", test_version2: "9.2.6249.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.2.6250.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "10.0.0.0", test_version2: "10.0.6412.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.6413.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "10.1.0.0", test_version2: "10.1.6503.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.1.6504.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
