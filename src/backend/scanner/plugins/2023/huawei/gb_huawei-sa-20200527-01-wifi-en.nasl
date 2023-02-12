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
  script_oid("1.3.6.1.4.1.25623.1.0.104507");
  script_version("2023-02-02T10:09:00+0000");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-01 13:33:19 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 19:15:00 +0000 (Tue, 11 Aug 2020)");

  script_cve_id("CVE-2019-15126");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Information Disclosure Vulnerability (huawei-sa-20200527-01-wifi-en, Kr00k)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Huawei Data Communication devices are prone to an information
  disclosure vulnerability dubbed 'Kr00k'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered on Broadcom Wi-Fi client devices.

  Specifically timed and handcrafted traffic can cause internal errors (related to state
  transitions) in a WLAN device.");

  script_tag(name:"impact", value:"The flaw lead to improper layer 2 Wi-Fi encryption with a
  consequent possibility of information disclosure over the air for a discrete set of traffic.");

  script_tag(name:"affected", value:"AP7030DE versions V200R005C20, V200R006C00, V200R006C10, V200R006C20,
  V200R007C10, V200R007C20, V200R008C00, V200R008C10, V200R010C00, V200R019C00

  AP9330DN versions V200R005C20, V200R006C00, V200R006C10, V200R006C20, V200R007C10, V200R007C20,
  V200R008C00, V200R008C10, V200R010C00, V200R019C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200527-01-wifi-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ap7030de_firmware",
                     "cpe:/o:huawei:ap9330dn_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe == "cpe:/o:huawei:ap7030de_firmware" ||
    cpe == "cpe:/o:huawei:ap9330dn_firmware") {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C00" || version =~ "^V200R006C10" || version =~ "^V200R006C20" ||
     version =~ "^V200R007C10" || version =~ "^V200R007C20" || version =~ "^V200R008C00" || version =~ "^V200R008C10" ||
     version =~ "^V200R010C00" || version =~ "^V200R019C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R019C00SPC800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
