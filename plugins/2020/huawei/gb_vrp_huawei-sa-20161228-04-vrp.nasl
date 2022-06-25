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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143947");
  script_version("2020-05-20T05:19:53+0000");
  script_tag(name:"last_modification", value:"2020-05-22 09:10:29 +0000 (Fri, 22 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 05:12:35 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-8785");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VRP Data Communication: Input Validation Vulnerability (huawei-sa-20161228-04-vrp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei devices are prone to an input validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to the lack of input validation, an attacker may craft a malformed
  packet and send it to the device using VRP, causing the device to display additional memory data and possibly
  leading to sensitive information leakage.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to make the device display
  additional memory data, possibly leading to sensitive information leakage.");

  script_tag(name:"affected", value:"Huawei S12700, S5700, S7700 and S9700.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161228-04-vrp-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s9700_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:s12700_firmware") {
  if (version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5700_firmware") {
  if (version == "V200R007C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s7700_firmware") {
  if (version == "V200R002C00" || version == "V200R005C00" || version == "V200R006C00" ||
      version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s9700_firmware") {
  if (version == "V200R007C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
