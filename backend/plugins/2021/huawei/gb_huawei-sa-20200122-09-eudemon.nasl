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
  script_oid("1.3.6.1.4.1.25623.1.0.145193");
  script_version("2021-01-22T09:19:18+0000");
  script_tag(name:"last_modification", value:"2021-01-22 11:28:48 +0000 (Fri, 22 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 02:12:55 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-1866");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Out of Bounds Read Vulnerability in Several Products (huawei-sa-20200122-09-eudemon)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an out-of-bounds read vulnerability in several products.");

  script_tag(name:"insight", value:"The software reads data past the end of the intended buffer when parsing
  certain crafted DHCP messages. Successful exploit could cause certain service abnormal.");

  script_tag(name:"impact", value:"Successful exploit could cause certain service abnormal.");

  script_tag(name:"affected", value:"NIP6800 versions V500R001C30 V500R001C60SPC500 V500R005C00

  S12700 versions V200R008C00

  S2700 versions V200R008C00

  S5700 versions V200R008C00

  S6700 versions V200R008C00

  S7700 versions V200R008C00

  S9700 versions V200R008C00

  Secospace USG6600 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500 V500R005C00

  USG9500 versions V500R001C30SPC300 V500R001C30SPC600 V500R001C60SPC500 V500R005C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200122-09-eudemon-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe == "cpe:/o:huawei:s12700_firmware" || cpe == "cpe:/o:huawei:s2700_firmware" ||
    cpe == "cpe:/o:huawei:s5700_firmware" || cpe == "cpe:/o:huawei:s6700_firmware" ||
    cpe == "cpe:/o:huawei:s7700_firmware" || cpe == "cpe:/o:huawei:s9700_firmware") {
  if (version =~ "^V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R013C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg6600_firmware") {
  if (version =~ "^V500R001C30SPC200" || version =~ "^V500R001C30SPC600" || version =~ "^V500R001C60SPC500" ||
      version =~ "^V500R005C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R005C20SPC300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg9500_firmware") {
  if (version =~ "^V500R001C30SPC300" || version =~ "^V500R001C30SPC600" || version =~ "^V500R001C60SPC500" ||
      version =~ "V500R005C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R005C20SPC300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
