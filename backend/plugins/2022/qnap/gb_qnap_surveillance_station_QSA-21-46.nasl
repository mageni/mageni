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

CPE = "cpe:/a:qnap:surveillance_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147384");
  script_version("2022-01-11T02:48:56+0000");
  script_tag(name:"last_modification", value:"2022-01-11 02:48:56 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-11 02:43:59 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-38687");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Just get the major version

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Surveillance Station Buffer Overflow Vulnerability (QSA-21-46)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_qnap_nas_surveillance_station_detect.nasl");
  script_mandatory_keys("qnap/surveillance/detected");

  script_tag(name:"summary", value:"QNAP QTS Surveillance Station is prone to a stack buffer
  overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A stack buffer overflow vulnerability has been reported to
  affect QNAP NAS running Surveillance Station. If exploited, this vulnerability allows attackers
  to execute arbitrary code.");

  script_tag(name:"affected", value:"QNAP QTS Surveillance Station prior to versions 5.1.5.3.6,
  5.1.5.4.6, 5.2.0.3.2 or 5.2.0.4.2.");

  script_tag(name:"solution", value:"Update to version 5.1.5.3.6, 5.1.5.4.6, 5.2.0.3.2, 5.2.0.4.2
  or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-46");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.5.3.6 / 5.1.5.4.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^5\.2\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.0.3.2 / 5.2.0.4.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
