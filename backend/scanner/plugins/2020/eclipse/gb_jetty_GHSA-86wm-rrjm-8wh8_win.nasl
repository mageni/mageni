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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144927");
  script_version("2020-11-30T06:14:54+0000");
  script_tag(name:"last_modification", value:"2020-11-30 11:17:04 +0000 (Mon, 30 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-30 06:14:12 +0000 (Mon, 30 Nov 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2020-27218");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Gzip Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a vulnerability where the buffer is not correctly
  recycled in Gzip Request inflation.");

  script_tag(name:"insight", value:"If GZIP request body inflation is enabled and requests from different clients
  are multiplexed onto a single connection and if an attacker can send a request with a body that is received
  entirely by not consumed by the application, then a subsequent request on the same connection will see that body
  prepended to it's body.

  The attacker will not see any data, but may inject data into the body of the subsequent request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty versions 9.4.0.RC0 - 9.4.34.v20201102, 10.0.0.alpha0 -
  10.0.0.beta2 and 11.0.0.alpha0 - 11.0.0.beta2.");

  script_tag(name:"solution", value:"Update to versions 9.4.35.v20201120, 10.0.0.beta3, 11.0.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-86wm-rrjm-8wh8");
  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=568892");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
                                          exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "9.4.0", test_version2: "9.4.34.20201102")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.35.20201120", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
