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
  script_oid("1.3.6.1.4.1.25623.1.0.108780");
  script_version("2020-06-06T12:33:09+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-15333", "CVE-2017-15346");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Two DOS Vulnerabilities of XML Parser in Some Huawei Products (huawei-sa-20171201-01-xml)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"XML parser have two DOS vulnerabilities in some Huawei products.");

  script_tag(name:"insight", value:"XML parser have two DOS vulnerabilities in some Huawei products. An attacker may craft specific XML files to the affected products. Due to not check the specially XML file and to parse this file, successful exploit will result in DOS attacks. (Vulnerability ID: HWPSIRT-2017-03037 and HWPSIRT-2017-03038)Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to lead to DoS attacks.");

  script_tag(name:"affected", value:"DBS3900 TDD LTE versions V100R003C00 V100R004C10

S12700 versions V200R005C00

S1700 versions V200R009C00 V200R010C00

S2300 versions V100R006C03 V100R006C05 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00 V200R010C00

S3300 versions V100R006C03 V100R006C05

S3700 versions V100R006C03 V100R006C05

S5300 versions V200R001C00 V200R003C00 V200R003C02 V200R005C00 V200R005C03 V200R005C05 V200R006C00 V200R007C00 V200R008C00 V200R009C00 V200R010C00

S5700 versions V200R001C00 V200R002C00 V200R003C00 V200R003C02 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00 V200R010C00

S600-E versions V200R008C00 V200R009C00 V200R010C00

S6300 versions V200R001C00 V200R003C00 V200R005C00 V200R005C02 V200R007C00 V200R008C00 V200R009C00 V200R010C00

S6700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00 V200R005C02 V200R008C00 V200R009C00 V200R010C00

S7700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00 V200R010C00

S9300 versions V200R001C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S9700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00 V200R010C00

eCNS210_TD versions V100R004C10 V100R004C10SPC003 V100R004C10SPC100 V100R004C10SPC101 V100R004C10SPC102 V100R004C10SPC200 V100R004C10SPC221 V100R004C10SPC400");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171201-01-xml-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s3700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe == "cpe:/o:huawei:s12700_firmware") {
  if (version == "V200R005C00" || version == "V200R006C00" || version == "V200R007C00" ||
      version == "V200R008C00" || version == "V200R009C00" || version == "V200R010C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V2R11C10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s1700_firmware") {
  if (version == "V200R009C00" || version == "V200R010C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V2R11C10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s3700_firmware") {
  if (version == "V100R006C03" || version == "V100R006C05") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V2R11C10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5700_firmware") {
  if (version == "V200R001C00" || version == "V200R002C00" || version == "V200R003C00" ||
      version == "V200R003C02" || version == "V200R005C00" || version == "V200R006C00" ||
      version == "V200R007C00" || version == "V200R008C00" || version == "V200R009C00" ||
      version == "V200R010C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V2R11C10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s6700_firmware") {
  if (version == "V200R001C00" || version == "V200R002C00" || version == "V200R003C00" ||
      version == "V200R005C00" || version == "V200R005C02" || version == "V200R008C00" ||
      version == "V200R009C00" || version == "V200R010C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V2R11C10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:s[79]700_firmware") {
  if (version == "V200R001C00" || version == "V200R002C00" || version == "V200R003C00" ||
      version == "V200R005C00" || version == "V200R006C00" || version == "V200R007C00" ||
      version == "V200R008C00" || version == "V200R009C00" || version == "V200R010C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V2R11C10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
