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

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127173");
  script_version("2022-09-08T05:21:36+0000");
  script_tag(name:"last_modification", value:"2022-09-08 05:21:36 +0000 (Thu, 08 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-07 08:04:00 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-36045");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB < 1.19.8, 2.x < 2.0.1 Account Takeover Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_detect.nasl");
  script_mandatory_keys("NodeBB/installed");

  script_tag(name:"summary", value:"NodeBB is prone to an account takeover vulnerability via a
  cryptographically weak PRNG in 'utils.generateUUID'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"utils.generateUUID, a helper function uses a cryptographically
  insecure pseudo-random number generator, which means that a specially crafted script combined
  with multiple invocations of the password reset functionality could enable an attacker to
  correctly calculate the reset code for an account they do not have access to.");

  script_tag(name:"impact", value:"The vulnerability allows an attacker to take over any account
  without the involvement of the victim.");

  script_tag(name:"affected", value:"NodeBB version 1.19.7 and prior and version 2.0.0.");

  script_tag(name:"solution", value:"Update to version 1.19.8, 2.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/security/advisories/GHSA-p4cc-w597-6cpm");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.19.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.19.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
