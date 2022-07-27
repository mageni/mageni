###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symfony_mult_vuln_aug18.nasl 12068 2018-10-25 07:21:15Z mmartin $
#
# Symfony <= 2.7.37, 2.8.* <= 2.8.30, 3.* <= 3.2.13 and 3.3.* <= 3.3.12 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113246");
  script_version("$Revision: 12068 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 09:21:15 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 12:27:08 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-16653", "CVE-2017-16654", "CVE-2017-16790");

  script_name("Symfony <= 2.7.37, 2.8.* <= 2.8.30, 3.* <= 3.2.13 and 3.3.* <= 3.3.12 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - An attacker can use the locale parameter to naivate to arbitrary directions.

  - An attacker can insert a file path into the 'FileType' POST parameter
      to retrieve the contents of that file.

  - The CSRF protection doesn't use different tokens for HTTP and HTTPS,
      allowing for MITM attacks on HTTP that can then be used in an HTTPS context.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to obtain sensitive information.");
  script_tag(name:"affected", value:"Symfony through version 2.7.37, 2.8.0 through 2.8.30, 3.0.0 through 3.2.13
  and 3.3.0 through 3.3.12.");
  script_tag(name:"solution", value:"Update to version 2.7.38, 2.8.31, 3.2.14 or 3.3.13 respectively.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2017-16653-csrf-protection-does-not-use-different-tokens-for-http-and-https");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2017-16790-ensure-that-submitted-data-are-uploaded-files");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.7.38" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.38" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.30" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.31" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.2.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.14" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.13" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
