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
  script_oid("1.3.6.1.4.1.25623.1.0.113996");
  script_version("2022-05-11T12:42:09+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:56:58 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 12:37:41 +0000 (Wed, 11 May 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2022-22970", "CVE-2022-22971");

  script_name("VMware Spring Framework < 5.2.22, 5.3.x < 5.3.20 Multiple DoS Vulnerabilities - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_spring_framework_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("vmware/spring/framework/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://spring.io/blog/2022/05/11/spring-framework-5-3-20-and-5-2-22-available-now");
  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22970");
  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22971");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to multiple denial of
  service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-22970: Spring Framework DoS via Data Binding to MultipartFile or Servlet Part

  Denial of Service (DoS) attack in Spring MVC or Spring WebFlux applications that handle file
  uploads and rely on data binding to set a MultipartFile or javax.servlet.Part to a field in a
  model object.

  - CVE-2022-22971: Spring Framework DoS with STOMP over WebSocket

  Denial of service (DoS) attack by authenticated users in Spring applications with a STOMP over
  WebSocket endpoint.");

  script_tag(name:"affected", value:"VMware Spring Framework versions prior to 5.2.22 and 5.3.x
  prior to 5.3.20.");

  script_tag(name:"solution", value:"Update to version 5.2.22, 5.3.20 or later.");

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

if( version_is_less( version:version, test_version:"5.2.22" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.2.22/5.3.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"5.3.0", test_version_up:"5.3.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.3.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
