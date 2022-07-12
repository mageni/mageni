# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:huawei:s";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142505");
  script_version("2020-06-05T06:56:36+0000");
  script_tag(name:"last_modification", value:"2020-06-05 10:05:11 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"creation_date", value:"2019-06-26 03:10:43 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-5285");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: DoS Vulnerability in Huawei S Series Switch Products (huawei-sa-20190522-01-switch)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Huawei S Series Switches are prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"An unauthenticated remote attacker can send crafted packets to the affected
  device to exploit this vulnerability. Due to insufficient verification of the packets, successful exploitation
  may cause the device reboot and denial of service (DoS) condition.");

  script_tag(name:"impact", value:"Successful exploitation may cause the device reboot and denial of service
  (DoS) condition.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_tag(name:"affected", value:"Multiple Huawei S Series Switches. For an extended list of vulnerable
  products please see the referenced vendor advisory.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190522-01-switch-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos['cpe'];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (CPE =~ "^cpe:/o:huawei:s127[0-9]{2}") {
  if (version =~ "^v200r00[567]c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c00") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013c00spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013c00spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s17[02][0-9]") {
  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^v200r009c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c00") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013c00spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013c00spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s23[0-9]{2}") {
  if (version =~ "^v200r003c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r005c00") &&
      version_is_less(version: version, test_version: "v200r005sph025")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s27[0-9]{2}") {
  if (version_is_greater_equal(version: version, test_version: "v200r005c00") &&
      version_is_less(version: version, test_version: "v200r005sph025")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^v200r00[67]c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s53[0-9]{2}") {
  if (version =~ "^v200r003c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r005c00") &&
      version_is_less(version: version, test_version: "v200r005sph025")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s57[0-9]{2}") {
  if (version =~ "^v200r003c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r005c00") &&
      version_is_less(version: version, test_version: "v200r005sph025")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^v200r00[67]c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s6[25][0-9]") {
  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s63[0-9]{2}") {
  if (version =~ "^v200r003c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r005c00") &&
      version_is_less(version: version, test_version: "v200r005sph025")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^v200r007c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s67[0-9]{2}") {
  if (version =~ "^v200r003c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r005c00") &&
      version_is_less(version: version, test_version: "v200r005sph025")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r005sph025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^v200r007c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s77[0-9]{2}") {
  if (version =~ "^v200r00[3567]c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s79[0-9]{2}") {
  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s93[0-9]{2}") {
  if (version =~ "^v200r003c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (CPE =~ "^cpe:/o:huawei:s97[0-9]{2}") {
  if (version =~ "^v200r00[3567]c00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r008c00") &&
      version_is_less(version: version, test_version: "v200r008sph021")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r008sph021");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r010c00") &&
      version_is_less(version: version, test_version: "v200r010sph017")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r010sph017");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r011c10") &&
      version_is_less(version: version, test_version: "v200r011sph009")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r011sph009");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r012c00") &&
      version_is_less(version: version, test_version: "v200r012sph003")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r012sph003");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "v200r013c00") &&
      version_is_less(version: version, test_version: "v200r013spc500")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "v200r013spc500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
