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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147549");
  script_version("2022-02-01T02:38:46+0000");
  script_tag(name:"last_modification", value:"2022-02-01 11:05:08 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 02:06:57 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");

  script_cve_id("CVE-2021-40033");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Information Exposure Vulnerability on Several Huawei Products (huawei-sa-20220112-01-infodis)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an information exposure vulnerability on several
  Huawei Products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The software does not properly protect certain information.");

  script_tag(name:"impact", value:"Successful exploit could cause information disclosure.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V200R005C10SPC800

  CloudEngine 5800 versions V200R005C10SPC800, V200R019C00SPC800

  CloudEngine 6800 versions V200R005C10SPC800, V200R005C20SPC800, V200R019C00SPC800

  CloudEngine 7800 versions V200R005C10SPC800, V200R019C00SPC800");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20220112-01-infodis-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:cloudengine_12800_firmware") {
  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH021")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH021");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (cpe =~ "^cpe:/o:huawei:cloudengine_[57]800_firmware") {
  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH021")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH021");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R019C00SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R019C00SPC800", fixed_patch: "V200R019SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_6800_firmware") {
  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH021")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH021");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R005C20SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH021")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C20SPC800", fixed_patch: "V200R005SPH021");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R019C00SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R019C00SPC800", fixed_patch: "V200R019SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
