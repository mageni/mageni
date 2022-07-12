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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117292");
  script_version("2021-04-07T09:01:03+0000");
  script_tag(name:"last_modification", value:"2021-04-07 10:26:17 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-07 08:45:48 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-2509");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS 4.5.x Command Injection Vulnerability (CVE-2020-2509)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to a command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw allows a remote attacker with access to the
  web server (default port 8080) to execute arbitrary shell commands, without prior
  knowledge of the web credentials.");

  script_tag(name:"affected", value:"QNAP QTS 4.5.x.");

  script_tag(name:"solution", value:"Update to version 4.5.1.1495 Build 20201123,
  4.5.2.1566 Build 20210202 or later.");

  script_xref(name:"URL", value:"https://threatpost.com/qnap-nas-devices-zero-day-attack/165165/");
  script_xref(name:"URL", value:"https://securingsam.com/new-vulnerabilities-allow-complete-takeover/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version !~ "^4\.5\.[0-2]")
  exit(0);

if (version_is_less(version: version, test_version: "4.5.1_20201123")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1_20201123");
  security_message(port: 0, data: report);
  exit(0);
}

else if (version =~ "^4\.5\.2" && version_is_less(version: version, test_version: "4.5.2_20210202")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.2_20210202");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
