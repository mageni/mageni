###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_dos_vuln_oct18_lin.nasl 13913 2019-02-27 16:43:39Z cfischer $
#
# PostgreSQL 7.4 < 7.4.19, 8.0 < 8.0.15, 8.1 < 8.1.11, 8.2 < 8.2.6 Multiple Vulnerabilities (Linux)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113282");
  script_version("$Revision: 13913 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 17:43:39 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-10-30 15:32:24 +0200 (Tue, 30 Oct 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2007-6600", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-4769", "CVE-2007-6601");
  script_bugtraq_id(27163);

  script_name("PostgreSQL 7.4 < 7.4.19, 8.0 < 8.0.15, 8.1 < 8.1.11, 8.2 < 8.2.6 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple Privilege Escalation and Denial of Service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PostgreSQL 7.4.0 through 7.4.18, 8.0.0 through 8.0.14, 8.1.0 through 8.1.10
  and 8.2.0 through 8.2.5.");

  script_tag(name:"solution", value:"Update to version 7.4.19, 8.0.15, 8.1.11 or 8.2.6 respectively.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/485864/100/0/threaded");

  exit(0);
}

CPE = "cpe:/a:postgresql:postgresql";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_in_range( version: version, test_version: "7.4.0", test_version2: "7.4.18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.4.19" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.0.0", test_version2: "8.0.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.15" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.1.0", test_version2: "8.1.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.1.11" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.2.0", test_version2: "8.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.6" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );