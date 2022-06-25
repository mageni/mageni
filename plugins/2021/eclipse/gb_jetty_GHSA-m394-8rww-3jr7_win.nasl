# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145468");
  script_version("2021-03-02T02:48:03+0000");
  script_tag(name:"last_modification", value:"2021-03-02 12:14:25 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-02 02:47:24 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-27223");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty DoS Vulnerability (GHSA-m394-8rww-3jr7) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"When Jetty handles a request containing request headers with a large number
  of 'quality' (i.e. q) parameters (such as what are seen on the Accept, Accept-Encoding, and Accept-Language
  request headers), the server may enter a denial of service (DoS) state due to high CPU usage while sorting
  the list of values based on their quality values. A single request can easily consume minutes of CPU time
  before it is even dispatched to the application.

  See the referenced vendor advisory for further information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty versions 9.4.6.v20170531 - 9.4.36.v20210114, 10.0.0 and 11.0.0.");

  script_tag(name:"solution", value:"Update to version 9.4.37.v20210219, 10.0.1, 11.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-m394-8rww-3jr7");
  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=571128");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "9.4.6.20170531", test_version2: "9.4.36.20210114")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.37.20210219", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "10.0.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "11.0.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
