###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_e107_mult_vuln.nasl 12998 2019-01-09 13:46:07Z asteins $
#
# e107 <= 2.1.8 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112373");
  script_version("2019-03-22T15:58:59+0000");
  script_tag(name:"last_modification", value:"2019-03-22 15:58:59 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-09-11 14:34:11 +0200 (Tue, 11 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-15901", "CVE-2018-16381");

  script_name("e107 <= 2.1.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");

  script_tag(name:"summary", value:"E107 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of the CSRF vulnerability could result
  in an attacker being able to change details such as passwords of users including administrators (CVE-2018-15901).

  A cross-site scripting (XSS) vulnerability exists due to insufficient sanitization in the 'user_loginname'
  parameter (CVE-2018-16381).");

  script_tag(name:"affected", value:"e107 versions through 2.1.8.");

  script_tag(name:"solution", value:"No known solution is available as of 22nd March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/dhananjay-bajaj/e107_2.1.8_csrf");
  script_xref(name:"URL", value:"https://github.com/dhananjay-bajaj/E107-v2.1.8-XSS-POC");

  exit(0);
}

CPE = "cpe:/a:e107:e107";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.1.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
