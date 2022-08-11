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
  script_oid("1.3.6.1.4.1.25623.1.0.143983");
  script_version("2020-05-27T07:48:04+0000");
  script_tag(name:"last_modification", value:"2020-05-29 08:52:53 +0000 (Fri, 29 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 03:09:54 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-17165");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: IPv6 Out-of-bounds Read Vulnerability (huawei-sa-20171213-01-ipv6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone an out-of-bounds read vulnerability in the
  IPv6 implementation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated attacker may send crafted malformed IPv6 packets to the
  affected products. Due to insufficient verification of the packets, successful exploit will cause device to
  reset.");

  script_tag(name:"impact", value:"Attacker can exploit this vulnerability to cause device reset.");

  script_tag(name:"affected", value:"Huawei Quidway S2700, Quidway S5300, Quidway S5700, S2300, S2700,
  S5300, S5700, S600-E, S6300 and S6700.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-01-ipv6-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:quidway_s2700_firmware",
                     "cpe:/o:huawei:quidway_s5300_firmware",
                     "cpe:/o:huawei:quidway_s5700_firmware",
                     "cpe:/o:huawei:s2300_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5300_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s600-e_firmware",
                     "cpe:/o:huawei:s6300_firmware",
                     "cpe:/o:huawei:s6700_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe =~ "^cpe:/o:huawei:quidway_s(27|53|57)00_firmware") {
  if (version == "V200R003C00SPC300") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s2300_firmware") {
  if (version == "V200R003C00" || version == "V200R003C00SPC300T" || version == "V200R005C00" ||
      version == "V200R006C00" || version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s2700_firmware") {
  if (version == "V200R005C00" || version == "V200R006C00" || version == "V200R007C00" ||
      version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5300_firmware") {
  if (version == "V200R003C00" || version == "V200R003C00SPC300T" || version == "V200R003C00SPC600" ||
      version == "V200R003C02" || version == "V200R005C00" || version == "V200R005C01" ||
      version == "V200R005C02" || version == "V200R005C03" || version == "V200R005C05") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R006C00" || version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5700_firmware") {
  if (version == "V200R003C00" || version == "V200R003C00SPC316T" || version == "V200R003C00SPC600" ||
      version == "V200R003C02" || version == "V200R005C00" || version == "V200R005C01" ||
      version == "V200R005C02" || version == "V200R005C03") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R006C00" || version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s600-e_firmware") {
  if (version == "V200R008C00" || version == "V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s6300_firmware") {
  if (version == "V200R003C00" || version == "V200R005C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s6700_firmware") {
  if (version == "V200R003C00" || version == "V200R005C00" || version == "V200R005C01" ||
      version == "V200R005C02") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH013");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R007C00" || version == "V200R008C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R008C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version == "V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
