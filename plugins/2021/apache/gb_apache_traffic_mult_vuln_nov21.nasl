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

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147106");
  script_version("2021-11-05T05:23:57+0000");
  script_tag(name:"last_modification", value:"2021-11-08 11:22:01 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-05 05:11:13 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-37147", "CVE-2021-37148", "CVE-2021-37149", "CVE-2021-41585",
                "CVE-2021-43082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) 8.0.0 < 8.1.3, 9.0.0 < 9.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-37147 Request Smuggling - LF line ending

  - CVE-2021-37148 Request Smuggling - transfer encoding validation

  - CVE-2021-37149 Request Smuggling - multiple attacks

  - CVE-2021-41585 ATS stops accepting connections on FreeBSD

  - CVE-2021-43082 heap-buffer-overflow with stats-over-http plugin");

  script_tag(name:"affected", value:"Apache Traffic Server version 8.0.0 through 8.1.2 and 9.0.0
  through 9.1.0.");

  script_tag(name:"solution", value:"Update to version 8.1.3, 9.1.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/k01797hyncx53659wr3o72s5cvkc3164");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
