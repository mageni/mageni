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
  script_oid("1.3.6.1.4.1.25623.1.0.146164");
  script_version("2021-06-23T04:56:17+0000");
  script_tag(name:"last_modification", value:"2021-06-23 10:20:01 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-23 04:46:29 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-34428");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Session Vulnerability (GHSA-m6cp-vxjx-65j6) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a vulnerability in the session
  management.");

  script_tag(name:"insight", value:"If an exception is thrown from the SessionListener#sessionDestroyed()
  method, then the session ID is not invalidated in the session ID manager. On deployments with
  clustered sessions and multiple contexts this can result in a session not being invalidated. This
  can result in an application used on a shared computer being left logged in.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.40.v20210413 and prior, 10.x through
  10.0.2 and 11.x through 11.0.2.");

  script_tag(name:"solution", value:"Update to version 9.4.41.v20210516, 10.0.3, 11.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-m6cp-vxjx-65j6");

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

if (version_is_less(version: version, test_version: "9.4.41.20210516")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.41.20210516", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
