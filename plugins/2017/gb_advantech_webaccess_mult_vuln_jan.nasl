###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_webaccess_mult_vuln_jan.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Advantech WebAccess Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:advantech:advantech_webaccess";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106514");
  script_version("2019-04-06T12:52:40+0000");
  script_tag(name:"last_modification", value:"2019-04-06 12:52:40 +0000 (Sat, 06 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-01-13 14:10:12 +0700 (Fri, 13 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5152", "CVE-2017-5154", "CVE-2017-5175", "CVE-2017-7929");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Advantech WebAccess Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_advantech_webaccess_consolidation.nasl");
  script_mandatory_keys("advantech/webaccess/detected");
  script_tag(name:"summary", value:"Advantech WebAccess is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Advantech WebAccess is prone to multiple vulnerabilities:

  - SQL Injection (CVE-2017-5154)

  - Authentication Bypass (CVE-2017-5152)

  - DLL Hijacking (CVE-2017-5175)");

  script_tag(name:"impact", value:"A remote attacker may gain administrative access to the application and its
data files.");

  script_tag(name:"affected", value:"WebAccess versions prior to 8.2");

  script_tag(name:"solution", value:"Upgrade to Version 8.2 or later");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-012-01");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-045-01");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-124-03");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port(cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port ) )
  exit( 0 );

path = infos["location"];
vers = infos["version"];

if( version_is_less( version: vers, test_version: "8.2" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "8.2", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}
exit( 99 );
