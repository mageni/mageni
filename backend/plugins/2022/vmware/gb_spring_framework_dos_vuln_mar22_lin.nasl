# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:spring_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113876");
  script_version("2022-04-06T02:09:21+0000");
  script_tag(name:"last_modification", value:"2022-04-06 10:04:37 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-06 01:56:26 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2022-22950");

  script_name("VMware Spring Framework < 5.2.20, 5.3.x < 5.3.17 DoS Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_spring_framework_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("vmware/spring/framework/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22950");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible for a user to provide a specially crafted SpEL
  expression that may cause a denial of service condition.");

  script_tag(name:"affected", value:"VMware Spring Framework version 5.2.19 and prior and version
  5.3.x through 5.3.16.");

  script_tag(name:"solution", value:"Update to version 5.2.20, 5.3.17 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"5.2.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.2.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"5.3.0", test_version2:"5.3.16" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.3.17", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
