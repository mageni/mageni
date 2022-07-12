# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113721");
  script_version("2020-07-14T13:08:55+0000");
  script_tag(name:"last_modification", value:"2020-07-14 13:08:55 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-13 11:11:10 +0000 (Mon, 13 Jul 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15028", "CVE-2020-15029", "CVE-2020-15030", "CVE-2020-15031", "CVE-2020-15032", "CVE-2020-15033", "CVE-2020-15034", "CVE-2020-15035", "CVE-2020-15036", "CVE-2020-15037");

  script_name("NeDi < 2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nedi_detect.nasl");
  script_mandatory_keys("nedi/detected");

  script_tag(name:"summary", value:"NeDi is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities are exploitable via the following pages and parameters:

  - the xo parameter of Topology-Map.php (CVE-2020-15028)

  - the sn parameter of Assets-Management.php (CVE-2020-15029)

  - the rtr parameter of Topology-Routes.php (CVE-2020-15030)

  - the chg parameter of Assets-Management.php (CVE-2020-15031)

  - the id parameter of Monitoring-Incidents.php (CVE-2020-15032)

  - the ip parameter of snmpget.php (CVE-2020-15033)

  - the tet parameter of Monitoring-Setup.php (CVE-2020-15034)

  - the hde parameter of Monitoring-Map.php (CVE-2020-15035)

  - the dv parameter of Topology-Linked.php (CVE-2020-15036)

  - the page st parameter of Reports-Devices.php (CVE-2020-15037)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"NeDi through version 1.9C.");

  script_tag(name:"solution", value:"Update to version 2.0.");

  exit(0);
}

CPE = "cpe:/a:nedi:nedi";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
