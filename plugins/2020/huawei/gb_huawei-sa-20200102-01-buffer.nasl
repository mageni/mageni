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
  script_oid("1.3.6.1.4.1.25623.1.0.107847");
  script_version("2020-06-30T13:26:45+0000");
  script_tag(name:"last_modification", value:"2020-07-01 11:20:27 +0000 (Wed, 01 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-30 14:52:21 +0200 (Tue, 30 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-5304");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Buffer Error Vulnerability in Some Huawei Products (huawei-sa-20200102-01-buffer)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a buffer error vulnerability in some Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a buffer error vulnerability in some Huawei products. An unauthenticated, remote attacker could send specific MPLS Echo Request messages to the target products. Due to insufficient input validation of some parameters in the messages, successful exploit may cause the device to reset. (Vulnerability ID: HWPSIRT-2019-04074)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5304.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause the device to reset.");

  script_tag(name:"affected", value:"AR120-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR1200 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR1200-S versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR150 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR150-S versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR160 versions V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR200 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR200-S versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR2200 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR2200-S versions V200R003C01 V200R005C20 V200R006C10 V200R008C20 V200R008C50

  AR3200 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  AR3600 versions V200R006C10 V200R007C00 V200R008C20 V200R008C50

  IPS Module versions V500R001C20 V500R001C30

  NGFW Module versions V500R001C20 V500R002C00

  NIP6300 versions V500R001C20 V500R001C30

  NIP6600 versions V500R001C20 V500R001C30

  NetEngine16EX versions V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  S5700 versions V200R005C00 V200R005C02 V200R005C03 V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C00

  S6700 versions V200R005C00 V200R005C01 V200R005C02 V200R008C00 V200R010C00 V200R011C00

  SRG1300 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  SRG2300 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  SRG3300 versions V200R003C01 V200R005C20 V200R006C10 V200R007C00 V200R008C20 V200R008C50

  Secospace AntiDDoS8000 versions V500R001C20 V500R001C60 V500R005C00

  Secospace USG6300 versions V500R001C20 V500R001C30

  Secospace USG6500 versions V500R001C20 V500R001C30

  Secospace USG6600 versions V500R001C20 V500R001C30 V500R001C50 V500R001C60 V500R005C00.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200102-01-buffer-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar120-s_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar1200-s_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar150-s_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar200-s_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar2200-s_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:nip6300_firmware",
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:netengine16ex_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware",
                     "cpe:/o:huawei:antiddos8000_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar120-s_firmware")  {
  if(version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150-s_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200-s_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3600_firmware")  {
  if(version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ips_module_firmware")  {
  if(version == "V500R001C20" || version == "V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version == "V500R001C20" || version == "V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6300_firmware")  {
  if(version == "V500R001C20" || version == "V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version == "V500R001C20" || version == "V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:netengine16ex_firmware")  {
  if(version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version == "V200R005C00" || version == "V200R005C02" || version == "V200R005C03" || version == "V200R006C00" || version == "V200R007C00" || version == "V200R008C00" || version == "V200R010C00" || version == "V200R011C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version == "V200R005C00" || version == "V200R005C01" || version == "V200R005C02" || version == "V200R008C00" || version == "V200R010C00" || version == "V200R011C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version == "V200R003C01" || version == "V200R005C20" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:antiddos8000_firmware")  {
  if(version == "V500R001C20" || version == "V500R001C60" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version == "V500R001C20" || version == "V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6500_firmware")  {
  if(version == "V500R001C20" || version == "V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" || version == "V500R001C60" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
