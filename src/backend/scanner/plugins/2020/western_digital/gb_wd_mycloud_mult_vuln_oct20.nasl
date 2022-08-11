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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144847");
  script_version("2020-11-02T03:21:49+0000");
  script_tag(name:"last_modification", value:"2020-11-02 14:55:55 +0000 (Mon, 02 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-02 03:08:33 +0000 (Mon, 02 Nov 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-27158", "CVE-2020-27159", "CVE-2020-27160", "CVE-2020-25765", "CVE-2020-27744",
                "CVE-2020-12830");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products < 5.04.114 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Remote code execution in cgi_api.php that allowed escalation of privileges (CVE-2020-27158)

  - Remote code execution in DsdkProxy.php due to insufficient sanitization and insufficient validation of user
    input (CVE-2020-27159)

  - Remote code execution in AvailableApps.php that allowed escalation of privileges (CVE-2020-27160)

  - Remote code execution in reg_device.php due to insufficient validation of user input (CVE-2020-25765)

  - Remote code execution with resultant escalation of privileges (CVE-2020-27744)

  - Multiple stack buffer overflows that could allow an attacker to carry out escalation of privileges through
    unauthorized remote code execution (CVE-2020-12830)");

  script_tag(name:"affected", value:"Western Digital My Cloud Mirror Gen2, EX2 Ultra, EX4100, PR2100 and PR4100
  with firmware versions prior to 5.04.114.");

  script_tag(name:"solution", value:"Update to firmware version 5.04.114 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/productsecurity/wdc-20007-my-cloud-firmware-version-5-04-114");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "5.04.114")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.04.114");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
