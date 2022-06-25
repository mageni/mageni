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
  script_oid("1.3.6.1.4.1.25623.1.0.107848");
  script_version("2020-07-01T08:36:56+0000");
  script_tag(name:"last_modification", value:"2020-07-01 11:20:27 +0000 (Wed, 01 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-17174");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Algorithm Vulnerability in Some Huawei Products (huawei-sa-20180703-01-algorithm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a weak algorithm vulnerability in some Huawei products.");

  script_tag(name:"insight", value:"There is a weak algorithm vulnerability in some Huawei products. To exploit the vulnerability, a remote, unauthenticated attacker has to capture traffic between clients and the affected products. The attacker may launch the Bleichenbacher attack on RSA key exchange and decrypt the session key by some cryptanalytic operations and the previously captured TLS sessions. Successful exploit may cause information leak. (Vulnerability ID: HWPSIRT-2017-12135)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17174.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause information leak.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC700 V200R002C50SPC800

  CloudEngine 5800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC700 V200R002C50SPC800

  CloudEngine 6800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC600 V200R002C50SPC800

  CloudEngine 7800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC600 V200R002C50SPC800

  RSE6500 versions V500R002C00

  S12700 versions V200R007C00 V200R007C01 V200R008C00 V200R009C00 V200R010C00

  S1700 versions V200R006C10SPC100 V200R009C00SPC200 V200R010C00

  S2700 versions V200R006C00SPC100 V200R006C10 V200R007C00 V200R008C00 V200R009C00 V200R010C00

  S5700 versions V200R005C02B010 V200R005C03B020 V200R006C00SPC100 V200R007C00 V200R008C00 V200R009C00 V200R010C00

  S6700 versions V200R005C02B020 V200R008C00 V200R009C00

  S7700 versions V200R006C00SPC300 V200R007C00 V200R008C00 V200R009C00SPC500 V200R010C00

  S9700 versions V200R006C00SPC100 V200R007C00 V200R007C01B102 V200R008C00SPC500 V200R009C00 V200R010C00

  SoftCo versions V200R003C20SPCb00

  VP9660 versions V600R006C10

  eSpace U1981 versions V100R001C20SPC700 V200R003C20SPCb00 V200R003C30SPC500 V200R003C50");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180703-01-algorithm-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list("cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:rse6500_firmware",
                     "cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware",
                     "cpe:/o:huawei:softco_firmware",
                     "cpe:/o:huawei:vp9660_firmware",
                     "cpe:/o:huawei:espace_u1981_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:cloudengine_12800_firmware")  {
  if(version == "V100R003C00SPC600" || version == "V100R003C10SPC100" || version == "V100R005C00SPC300" || version == "V100R005C10SPC200" || version == "V100R006C00SPC600" || version == "V200R001C00SPC700" || version == "V200R002C50SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003SPC810")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003SPC810");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_5800_firmware")  {
  if(version == "V100R003C00SPC600" || version == "V100R003C10SPC100" || version == "V100R005C00SPC300" || version == "V100R005C10SPC200" || version == "V100R006C00SPC600" || version == "V200R001C00SPC700" || version == "V200R002C50SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003SPC810")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003SPC810");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_6800_firmware")  {
  if(version == "V100R003C00SPC600" || version == "V100R003C10SPC100" || version == "V100R005C00SPC300" || version == "V100R005C10SPC200" || version == "V100R006C00SPC600" || version == "V200R001C00SPC600" || version == "V200R002C50SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003SPC810")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003SPC810");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_7800_firmware")  {
  if(version == "V100R003C00SPC600" || version == "V100R003C10SPC100" || version == "V100R005C00SPC300" || version == "V100R005C10SPC200" || version == "V100R006C00SPC600" || version == "V200R001C00SPC600" || version == "V200R002C50SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003SPC810")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003SPC810");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:rse6500_firmware")  {
  if(version == "V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s12700_firmware")  {
  if(version == "V200R007C00" || version == "V200R007C01" || version == "V200R008C00" || version == "V200R009C00" || version == "V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R12C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R12C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s1700_firmware")  {
  if(version == "V200R006C10SPC100" || version == "V200R009C00SPC200" || version == "V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R12C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R12C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s2700_firmware")  {
  if(version == "V200R006C00SPC100" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C00" || version == "V200R009C00" || version == "V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R12C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R12C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version == "V200R005C02B010" || version == "V200R005C03B020" || version == "V200R006C00SPC100" || version == "V200R007C00" || version == "V200R008C00" || version == "V200R009C00" || version == "V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R12C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R12C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version == "V200R005C02B020" || version == "V200R008C00" || version == "V200R009C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R12C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R12C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s7700_firmware")  {
  if(version == "V200R006C00SPC300" || version == "V200R007C00" || version == "V200R008C00" || version == "V200R009C00SPC500" || version == "V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R12C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R12C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9700_firmware")  {
  if(version == "V200R006C00SPC100" || version == "V200R007C00" || version == "V200R007C01B102" || version == "V200R008C00SPC500" || version == "V200R009C00" || version == "V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R12C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R12C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:softco_firmware")  {
  if(version == "V200R003C20SPCB00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003C50SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003C50SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:vp9660_firmware")  {
  if(version == "V600R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C10SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C10SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:espace_u1981_firmware")  {
  if(version == "V100R001C20SPC700" || version == "V200R003C20SPCB00" || version == "V200R003C30SPC500" || version == "V200R003C50") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003C50SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003C50SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

