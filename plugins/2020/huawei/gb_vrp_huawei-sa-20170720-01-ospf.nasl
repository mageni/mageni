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
  script_oid("1.3.6.1.4.1.25623.1.0.143950");
  script_version("2020-05-25T09:53:26+0000");
  script_tag(name:"last_modification", value:"2020-05-25 10:43:28 +0000 (Mon, 25 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 07:44:20 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-8147");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VRP Data Communication: MaxAge LSA Vulnerability (huawei-sa-20170720-01-ospf)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to a MaxAge LSA vulnerability due to an
  improper OSPF implementation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When the device receives special LSA packets, the LS (Link Status) age would
  be set to MaxAge, 3600 seconds. An attacker can exploit this vulnerability to poison the route table and
  launch a DoS attack.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to poison the route table and
  launch a DoS attack.");

  script_tag(name:"affected", value:"Huawei AC6005, AC6605, AR1200, AR200, AR3200, CloudEngine 12800,
  CloudEngine 5800, CloudEngine 6800, CloudEngine 7800, CloudEngine 8800, E600, NE20E-S, S12700, S1700,
  S2300, S2700, S5300, S5700, S6300, S6700, S7700, S9300, S9700 and Secospace USG6600.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170720-01-ospf-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:cloudengine_8800_firmware",
                     "cpe:/o:huawei:ne20e-s_firmware",
                     "cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s2300_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5300_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6300_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9300_firmware",
                     "cpe:/o:huawei:s9700_firmware",
                     "cpe:/o:huawei:usg6600_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar1200_firmware") {
  if (version == "V200R005C10CP0582T" || version == "V200R005C10HP0581T" || version == "V200R005C20SPC026T") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R007C00SPCb00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:ar(2|32)00_firmware") {
  if (version == "V200R005C20SPC026T") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R007C00SPCb00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:cloudengine_(128|58|68|78)00") {
  if (version == "V100R003C00" || version == "V100R005C00" || version == "V100R005C10" || version == "V100R006C00" ||
      version == "V200R001C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R002C50");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_8800_firmware") {
  if (version == "V100R006C00" || version == "V200R001C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R002C50");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ne20e-s_firmware") {
  if (version == "V800R005C01SPC100" || version == "V800R005C01SPC200" || version == "V800R006C00SPC300" ||
      version == "V800R007C00SPC200" || version == "V800R007C10SPC100" || version == "V800R008C10SPC300" ||
      version == "V800R008C10SPC500") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V800R009C10SPC200");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s12700_firmware") {
  if (version == "V200R005C00" || version == "V200R006C00" || version == "V200R007C00" ||
      version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s1700_firmware") {
  if (version == "V100R006C00" || version == "V100R007C00" || version == "V200R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:s(23|27)00_firmware") {
  if (version == "V100R005C00" || version == "V100R006C00" || version == "V100R006C03" ||
      version == "V100R006C05" || version == "V200R003C00" || version == "V200R003C02" ||
      version == "V200R003C10" || version == "V200R005C00" || version == "V200R005C01" ||
      version == "V200R005C02" || version == "V200R005C03" || version == "V200R006C00" ||
      version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:s(53|57)00_firmware") {
  if (version == "V100R005C00" || version == "V100R006C00" || version == "V100R006C01" ||
      version == "V200R001C00" || version == "V200R001C01" || version == "V200R002C00" ||
      version == "V200R003C00" || version == "V200R003C02" || version == "V200R003C10" ||
      version == "V200R005C00" || version == "V200R006C00" || version == "V200R007C00" ||
      version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s6300_firmware") {
  if (version == "V100R006C00" || version == "V200R001C00" || version == "V200R001C01" ||
      version == "V200R002C00" || version == "V200R003C00" || version == "V200R003C02" ||
      version == "V200R003C10" || version == "V200R005C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s6700_firmware") {
  if (version == "V100R006C00" || version == "V200R001C00" || version == "V200R001C01" ||
      version == "V200R002C00" || version == "V200R003C00" || version == "V200R003C02" ||
      version == "V200R003C10" || version == "V200R005C00" || version == "V200R006C00" ||
      version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "^cpe:/o:huawei:s7700_firmware") {
  if (version == "V100R003C00" || version == "V100R006C00" || version == "V200R001C00" ||
      version == "V200R001C01" || version == "V200R002C00" || version == "V200R003C00" ||
      version == "V200R005C00" || version == "V200R006C00" || version == "V200R007C00" ||
      version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s9300_firmware") {
  if (version == "V100R001C00" || version == "V100R002C00" || version == "V100R003C00" ||
      version == "V100R006C00" || version == "V200R001C00" || version == "V200R002C00" ||
      version == "V200R003C00" || version == "V200R005C00" || version == "V200R006C00" ||
      version == "V200R007C00" || version == "V200R008C00" || version == "V200R008C10") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s9700_firmware") {
  if (version == "V200R001C00" || version == "V200R002C00" || version == "V200R003C00" ||
      version == "V200R005C00" || version == "V200R006C00" || version == "V200R007C00" ||
      version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg6600_firmware") {
  if (version == "V500R001C00" || version == "V500R001C20" || version == "V500R001C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R001C60SPC300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
