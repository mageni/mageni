# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143194");
  script_version("2019-11-28T03:18:05+0000");
  script_tag(name:"last_modification", value:"2019-11-28 03:18:05 +0000 (Thu, 28 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-27 08:03:52 +0000 (Wed, 27 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-17632");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty XSS Vulnerability - CVE-2019-17632 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"The generic ErrorHandler within Jetty will produce a 'text/html' or 'text/json'
  response containing the Stacktrace of the unhandled error it encounters.

  This stacktrace is not properly escaped and can be used as an XSS attack vector by a skilled adversary.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.21.v20190926, 9.4.22.v20191022 and 9.4.23.v20191118.");

  script_tag(name:"solution", value:"Update to version 9.4.24.v20191120 or later.");

  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=553443");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
                                          exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_equal(version: version, test_version: "9.4.21.20190926") ||
    version_is_equal(version: version, test_version: "9.4.22.20191022") ||
    version_is_equal(version: version, test_version: "9.4.23.20191118")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.24.20191120", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
