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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145668");
  script_version("2021-03-29T07:18:00+0000");
  script_tag(name:"last_modification", value:"2021-03-30 10:22:27 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-29 06:32:37 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-22321");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Use After Free Vulnerability in Huawei Product (huawei-sa-20210210-01-uaf)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a use-after-free vulnerability in Huawei products.");

  script_tag(name:"insight", value:"A module cannot deal with specific operations in special scenarios.
  Attackers can exploit this vulnerability by performing malicious operations. This can cause memory
  use-after-free, compromising normal service.");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability by performing malicious operations.
  This can cause memory use-after-free, compromising normal service.");

  script_tag(name:"affected", value:"NIP6300 versions V500R001C30 V500R001C60

  NIP6600 versions V500R001C30

  NIP6800 versions V500R001C60

  S12700 versions V200R007C01 V200R007C01B102 V200R008C00 V200R010C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S1700 versions V200R009C00SPC200 V200R009C00SPC500 V200R010C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S2700 versions V200R008C00 V200R010C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S5700 versions V200R008C00 V200R010C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10 V200R011C10SPC100

  S6700 versions V200R008C00 V200R010C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10 V200R011C10SPC100

  S7700 versions V200R008C00 V200R010C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  S9700 versions V200R007C01 V200R007C01B102 V200R008C00 V200R010C00 V200R010C00SPC300 V200R011C00 V200R011C00SPC100 V200R011C10

  Secospace USG6300 versions V500R001C30 V500R001C60

  Secospace USG6500 versions V500R001C30 V500R001C60

  Secospace USG6600 versions V500R001C30 V500R001C60

  USG9500 versions V500R001C30 V500R001C60");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210210-01-uaf-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:s12700_firmware" || cpe == "cpe:/o:huawei:s9700_firmware")  {
  if(version =~ "^V200R007C01" || version =~ "^V200R007C01B102" || version =~ "^V200R008C00" ||
     version =~ "^V200R010C00" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C00" ||
     version =~ "^V200R011C00SPC100" || version =~ "^V200R011C10") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R013C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s1700_firmware")  {
  if(version =~ "^V200R009C00SPC200" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00" ||
     version =~ "^V200R010C00SPC300" || version =~ "^V200R011C00" || version =~ "^V200R011C00SPC100" ||
     version =~ "^V200R011C10") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R013C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s2700_firmware" || cpe == "cpe:/o:huawei:s7700_firmware")  {
  if(version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R010C00SPC300" ||
     version =~ "^V200R011C00" || version =~ "^V200R011C00SPC100" || version =~ "^V200R011C10") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R013C00SPC5000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5700_firmware" || cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R010C00SPC300" ||
     version =~ "^V200R011C00" || version =~ "^V200R011C00SPC100" || version =~ "^V200R011C10" ||
     version =~ "^V200R011C10SPC100") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R013C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg6300_firmware" || cpe == "cpe:/o:huawei:usg6500_firmware" ||
    cpe == "cpe:/o:huawei:usg6600_firmware" || cpe == "cpe:/o:huawei:usg9500_firmware")  {
  if(version =~ "^V500R001C30" || version =~ "^V500R001C60") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
