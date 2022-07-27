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
  script_oid("1.3.6.1.4.1.25623.1.0.147027");
  script_version("2021-10-29T03:13:22+0000");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-29 02:48:23 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-37129");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Out of Bounds Write Vulnerability in Some Huawei Products (huawei-sa-20211020-01-outofwrite)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an out of bounds write vulnerability in some Huawei
  products.");

  script_tag(name:"insight", value:"The vulnerability is caused by a function of a module that does
  not properly verify input parameter. Successful exploit could cause out of bounds write leading
  to a denial of service condition.");

  script_tag(name:"impact", value:"Successful exploit could cause out of bounds write leading to
  a denial of service condition.");

  script_tag(name:"affected", value:"IPS Module versions V500R005C00, V500R005C20

  NGFW Module versions V500R005C00

  NIP6600 versions V500R005C00, V500R005C20

  S12700 versions V200R010C00SPC600, V200R011C10SPC500, V200R011C10SPC600, V200R013C00SPC500,
  V200R019C00SPC200, V200R019C00SPC500, V200R019C10SPC200, V200R020C00, V200R020C10

  S1700 versions V200R010C00SPC600, V200R011C10SPC500, V200R011C10SPC600

  S2700 versions V200R010C00SPC600, V200R011C10SPC500, V200R011C10SPC600

  S5700 versions V200R010C00SPC600, V200R010C00SPC700, V200R011C10SPC500, V200R011C10SPC600,
  V200R019C00SPC500

  S6700 versions V200R010C00SPC600, V200R011C10SPC500, V200R011C10SPC600

  S7700 versions V200R010C00SPC600, V200R010C00SPC700, V200R011C10SPC500, V200R011C10SPC600

  S9700 versions V200R010C00SPC600, V200R011C10SPC500, V200R011C10SPC600

  USG9500 versions V500R005C00, V500R005C20");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20211020-01-outofwrite-en");

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
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:s12700_firmware")  {
  if (version =~ "^V200R010C00SPC600" || version =~ "^V200R011C10SPC500" ||
      version =~ "^V200R011C10SPC600" || version =~ "^V200R013C00SPC500" ||
      version =~ "^V200R019C00SPC200" || version =~ "^V200R019C00SPC500" ||
      version =~ "^V200R019C10SPC200") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R019C10SPC500", fixed_patch: "V200R019SPH029");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R020C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R020C10SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R020C10") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R019C10SPC500", fixed_patch: "V200R019SPH029");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s1700_firmware" || cpe == "cpe:/o:huawei:s2700_firmware" ||
    cpe == "cpe:/o:huawei:s6700_firmware")  {
  if (version =~ "^V200R010C00SPC600" || version =~ "^V200R011C10SPC500" ||
      version =~ "^V200R011C10SPC600") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R019C10SPC500", fixed_patch: "V200R019SPH029");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if (version =~ "^V200R010C00SPC600" || version =~ "^V200R010C00SPC700" ||
      version =~ "^V200R011C10SPC500" || version =~ "^V200R011C10SPC600" ||
      version =~ "^V200R019C00SPC500") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R019C10SPC500", fixed_patch: "V200R019SPH029");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s7700_firmware")  {
  if (version =~ "^V200R010C00SPC600" || version =~ "^V200R010C00SPC700" ||
      version =~ "^V200R011C10SPC500" || version =~ "^V200R011C10SPC600") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R019C10SPC500", fixed_patch: "V200R019SPH029");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s9700_firmware")  {
  if (version =~ "^V200R010C00SPC600" || version =~ "^V200R011C10SPC600") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R019C10SPC500", fixed_patch: "V200R019SPH029");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R011C10SPC500") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R020C10SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg9500_firmware")  {
  if (version =~ "^V500R005C00" || version =~ "^V500R005C20") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R005C20SPC601");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
