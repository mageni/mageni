# Copyright (C) 2023 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149144");
  script_version("2023-01-17T10:10:58+0000");
  script_tag(name:"last_modification", value:"2023-01-17 10:10:58 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-17 03:26:39 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-29841", "CVE-2022-29842", "CVE-2022-29843", "CVE-2022-29844");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.26.119 Multiple Vulnerabilities (WDC-23002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-29841: Remote code execution (RCE) that is caused by a command that read files from a
  privileged location and creates a system command without sanitizing the read data. This command
  could be triggered by an attacker remotely to cause code execution and gain a reverse shell.

  - CVE-2022-29842: Command injection that could allow an attacker to execute code in the context
  of the root user on a vulnerable CGI file.

  - CVE-2022-29843: Issue in the DDNS service configuration that could allow an attacker to execute
  code in the context of the root user.

  - CVE-2022-29844: Memory corruption in the FTP service that could allow an attacker to read and
  write arbitrary files. This could lead to a full NAS compromise and would give remote execution
  capabilities to the attacker.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud
  EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100, My Cloud
  EX2100, My Cloud and WD Cloud with firmware prior to version 5.26.119.");

  script_tag(name:"solution", value:"Update to firmware version 5.26.119 or later.");

  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.26.119");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-23002-my-cloud-firmware-version-5-26-119");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:wd_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.26.119")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.26.119");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
