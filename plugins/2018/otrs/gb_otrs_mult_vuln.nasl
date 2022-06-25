###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_mult_vuln.nasl 12523 2018-11-26 09:24:07Z mmartin $
#
# OTRS < 6.0.11, < 5.0.30, < 4.0.32 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112389");
  script_version("$Revision: 12523 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-26 10:24:07 +0100 (Mon, 26 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-01 12:12:22 +0200 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16586", "CVE-2018-16587");

  script_name("OTRS < 6.0.11, < 5.0.30, < 4.0.32 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - An attacker could send a malicious email to an OTRS system.
If a logged in user opens it, the email could cause the browser to load external image or CSS resources.

  - An attacker could send a malicious email to an OTRS system.
If a user with admin permissions opens it, it causes deletions of arbitrary files that the OTRS web server user has write access to.");
  script_tag(name:"affected", value:"OTRS 6.0.x up to and including 6.0.10, OTRS 5.0.x up to and including 5.0.29, and OTRS 4.0.x up to and including 4.0.31.");
  script_tag(name:"solution", value:"Update to OTRS version 6.0.11, 5.0.30 or 4.0.32 respectively.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-04-security-update-for-otrs-framework/");
  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-05-security-update-for-otrs-framework/");

  exit(0);
}

CPE = "cpe:/a:otrs:otrs";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.31" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.32" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.29" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.30" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.11" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
