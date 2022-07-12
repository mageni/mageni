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
  script_oid("1.3.6.1.4.1.25623.1.0.107849");
  script_version("2020-07-01T09:45:45+0000");
  script_tag(name:"last_modification", value:"2020-07-01 11:20:27 +0000 (Wed, 01 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-5254", "CVE-2019-5255", "CVE-2019-5256", "CVE-2019-5257", "CVE-2019-5258");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Five Vulnerabilities in Some Huawei Products (huawei-sa-20191211-01-ssp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an out-of-bounds read vulnerability in some Huawei products.");

  script_tag(name:"insight", value:"There is an out-of-bounds read vulnerability in some Huawei products. An attacker who logs in to the board may send crafted messages from the internal network port or tamper with inter-process message packets to exploit this vulnerability. Due to insufficient validation of the message, successful exploit may cause the affected board abnormal. (Vulnerability ID: HWPSIRT-2019-01067)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5254.There is a DoS vulnerability in some Huawei products. An attacker may send crafted messages from a FTP client to exploit this vulnerability. Due to insufficient validation of the message, successful exploit may cause the system out-of-bounds read and result in a denial of service condition of the affected service. (Vulnerability ID: HWPSIRT-2019-01071)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5255.There is a null pointer dereference vulnerability in some Huawei products. The system dereferences a pointer that it expects to be valid, but is NULL. A local attacker could exploit this vulnerability by sending crafted parameters. A successful exploit could cause a denial of service and the process reboot. (Vulnerability ID: HWPSIRT-2019-01072)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5256.There is a resource management vulnerability in some Huawei products. An attacker who logs in to the board may send crafted messages from the internal network port or tamper with inter-process message packets to exploit this vulnerability. Due to improper management of system resources, successful exploit may cause resource exhausted. (Vulnerability ID: HWPSIRT-2019-01073)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5257.There is a buffer overflow vulnerability in some Huawei products. An attacker who logs in to the board may send crafted messages from the internal network port or tamper with inter-process message packets to exploit this vulnerability. Due to insufficient validation of the message, successful exploit may cause the affected board abnormal. (Vulnerability ID: HWPSIRT-2019-01074)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5258.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause the affected board abnormal.

Successful exploit may cause the system out-of-bounds read and result in a denial of service condition of the affected service.

Successful exploit may cause a denial of service and the process reboot.

Successful exploit may cause resource exhausted.");

  script_tag(name:"affected", value:"AP2000 versions V200R005C30 V200R006C10 V200R006C20 V200R007C10 V200R007C20 V200R008C00 V200R008C10 V200R009C00

  IPS Module versions V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE V500R001C30 V500R001C30SPC100 V500R001C30SPC100PWE V500R001C30SPC200 V500R001C30SPC200PWE V500R001C30SPC300 V500R001C50 V500R001C50PWE V500R001C80 V500R005C00

  NGFW Module versions V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE V500R002C00 V500R002C00SPC100 V500R002C00SPC100PWE V500R002C00SPC200 V500R002C00SPC200PWE V500R002C00SPC300 V500R002C10 V500R002C10PWE V500R002C30 V500R002C30PWE V500R005C00

  NIP6300 versions V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE V500R001C30 V500R001C30SPC100 V500R001C30SPC100PWE V500R001C30SPC200 V500R001C30SPC200PWE V500R001C30SPC300 V500R001C50 V500R001C50PWE V500R001C80 V500R005C00

  NIP6600 versions V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C30 V500R001C30SPC100 V500R001C30SPC100PWE V500R001C30SPC200 V500R001C30SPC200PWE V500R001C30SPC300 V500R001C50 V500R001C50PWE V500R001C80 V500R005C00

  NIP6800 versions V500R001C50 V500R001C50PWE V500R001C80 V500R005C00

  S5700 versions V200R005C03

  SVN5600 versions V200R003C00SPC100

  SVN5800 versions V200R003C00SPC100

  SVN5800-C versions V200R003C00SPC100

  SeMG9811 versions V500R002C20 V500R002C30 V500R005C00

  Secospace AntiDDoS8000 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC600 V500R001C00SPC700 V500R001C00SPH303 V500R001C20SPC200 V500R001C20SPC300 V500R001C20SPC500 V500R001C20SPC600 V500R001C60SPC100 V500R001C60SPC101 V500R001C60SPC200 V500R001C60SPC300 V500R001C60SPC500 V500R001C60SPC600 V500R005C00 V500R005C00SPC100

  Secospace USG6300 versions V100R001C20SPC100 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC101 V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE V500R001C30 V500R001C30SPC100 V500R001C30SPC100PWE V500R001C30SPC200 V500R001C30SPC200PWE V500R001C30SPC300 V500R001C50 V500R001C50PWE V500R001C80 V500R001C80PWE V500R005C00

  Secospace USG6500 versions V100R001C20SPC100 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC101 V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE V500R001C30 V500R001C30SPC100 V500R001C30SPC100PWE V500R001C30SPC200 V500R001C30SPC200PWE V500R001C30SPC300 V500R001C50 V500R001C50PWE V500R001C80 V500R001C80PWE V500R005C00

  Secospace USG6600 versions V100R001C00SPC200 V100R001C10SPC200 V100R001C10SPC201 V100R001C20SPC100 V100R001C20SPC200 V500R001C00 V500R001C00SPC050 V500R001C00SPC090 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC101 V500R001C20SPC200 V500R001C20SPC200PWE V500R001C20SPC300 V500R001C20SPC300B078 V500R001C20SPC300PWE V500R001C30 V500R001C30SPC100 V500R001C30SPC100PWE V500R001C30SPC200 V500R001C30SPC200PWE V500R001C30SPC300 V500R001C30SPC500 V500R001C30SPC600 V500R001C30SPC600PWE V500R001C30SPC601 V500R001C50 V500R001C50PWE V500R001C50SPC009 V500R001C50SPC100 V500R001C50SPC100PWE V500R001C50SPC200 V500R001C50SPC200PWE V500R001C50SPC300 V500R001C60 V500R001C60SPC100 V500R001C60SPC100PWE V500R001C60SPC200 V500R001C60SPC200PWE V500R001C60SPC300 V500R001C60SPC500 V500R001C80 V500R001C80PWE V500R005C00 V500R005C00SPC100 V500R005C00SPC102

  USG6000V versions V500R001C10 V500R001C10SPC100 V500R001C10SPC200 V500R001C20 V500R001C20SPC100 V500R001C20SPC200 V500R001C20SPC300 V500R001C20SPC500 V500R001C20SPC600 V500R003C00 V500R003C00SPC100 V500R005C00 V500R005C00SPC100

  eSpace U1981 versions V200R003C50SPC700");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191211-01-ssp-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ap2000_firmware",
                     "cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:nip6300_firmware",
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:nip6800_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:svn5600_firmware",
                     "cpe:/o:huawei:svn5800_firmware",
                     "cpe:/o:huawei:svn5800-c_firmware",
                     "cpe:/o:huawei:semg9811_firmware",
                     "cpe:/o:huawei:antiddos8000_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg6000v_firmware",
                     "cpe:/o:huawei:espace_u1981_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ap2000_firmware")  {
  if(version == "V200R005C30" || version == "V200R006C10" || version == "V200R006C20" || version == "V200R007C10" || version == "V200R007C20" || version == "V200R008C00" || version == "V200R008C10" || version == "V200R009C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ips_module_firmware")  {
  if(version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPH303" || version == "V500R001C00SPH508" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC100PWE" || version == "V500R001C20SPC200" || version == "V500R001C20SPC200B062" || version == "V500R001C20SPC200PWE" || version == "V500R001C20SPC300B078" || version == "V500R001C20SPC300PWE" || version == "V500R001C30" || version == "V500R001C30SPC100" || version == "V500R001C30SPC100PWE" || version == "V500R001C30SPC200" || version == "V500R001C30SPC200PWE" || version == "V500R001C30SPC300" || version == "V500R001C50" || version == "V500R001C50PWE" || version == "V500R001C80" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPC500PWE" || version == "V500R001C00SPH303" || version == "V500R001C00SPH508" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC100PWE" || version == "V500R001C20SPC200" || version == "V500R001C20SPC200B062" || version == "V500R001C20SPC200PWE" || version == "V500R001C20SPC300B078" || version == "V500R001C20SPC300PWE" || version == "V500R002C00" || version == "V500R002C00SPC100" || version == "V500R002C00SPC100PWE" || version == "V500R002C00SPC200" || version == "V500R002C00SPC200PWE" || version == "V500R002C00SPC300" || version == "V500R002C10" || version == "V500R002C10PWE" || version == "V500R002C30" || version == "V500R002C30PWE" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6300_firmware")  {
  if(version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPH303" || version == "V500R001C00SPH508" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC100PWE" || version == "V500R001C20SPC200" || version == "V500R001C20SPC200B062" || version == "V500R001C20SPC200PWE" || version == "V500R001C20SPC300B078" || version == "V500R001C20SPC300PWE" || version == "V500R001C30" || version == "V500R001C30SPC100" || version == "V500R001C30SPC100PWE" || version == "V500R001C30SPC200" || version == "V500R001C30SPC200PWE" || version == "V500R001C30SPC300" || version == "V500R001C50" || version == "V500R001C50PWE" || version == "V500R001C80" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPH303" || version == "V500R001C00SPH508" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC100PWE" || version == "V500R001C20SPC200" || version == "V500R001C20SPC200B062" || version == "V500R001C20SPC200PWE" || version == "V500R001C20SPC300B078" || version == "V500R001C30" || version == "V500R001C30SPC100" || version == "V500R001C30SPC100PWE" || version == "V500R001C30SPC200" || version == "V500R001C30SPC200PWE" || version == "V500R001C30SPC300" || version == "V500R001C50" || version == "V500R001C50PWE" || version == "V500R001C80" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6800_firmware")  {
  if(version == "V500R001C50" || version == "V500R001C50PWE" || version == "V500R001C80" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version == "V200R005C03") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH026")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R005SPH026");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:svn5600_firmware")  {
  if(version == "V200R003C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:svn5800_firmware")  {
  if(version == "V200R003C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:svn5800-c_firmware")  {
  if(version == "V200R003C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:semg9811_firmware")  {
  if(version == "V500R002C20" || version == "V500R002C30" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:antiddos8000_firmware")  {
  if(version == "V500R001C00" || version == "V500R001C00SPC200" || version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPC600" || version == "V500R001C00SPC700" || version == "V500R001C00SPH303" || version == "V500R001C20SPC200" || version == "V500R001C20SPC300" || version == "V500R001C20SPC500" || version == "V500R001C20SPC600" || version == "V500R001C60SPC100" || version == "V500R001C60SPC101" || version == "V500R001C60SPC200" || version == "V500R001C60SPC300" || version == "V500R001C60SPC500" || version == "V500R001C60SPC600" || version == "V500R005C00" || version == "V500R005C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version == "V100R001C20SPC100" || version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPC500PWE" || version == "V500R001C00SPH303" || version == "V500R001C00SPH508" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC100PWE" || version == "V500R001C20SPC101" || version == "V500R001C20SPC200" || version == "V500R001C20SPC200B062" || version == "V500R001C20SPC200PWE" || version == "V500R001C20SPC300B078" || version == "V500R001C20SPC300PWE" || version == "V500R001C30" || version == "V500R001C30SPC100" || version == "V500R001C30SPC100PWE" || version == "V500R001C30SPC200" || version == "V500R001C30SPC200PWE" || version == "V500R001C30SPC300" || version == "V500R001C50" || version == "V500R001C50PWE" || version == "V500R001C80" || version == "V500R001C80PWE" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6500_firmware")  {
  if(version == "V100R001C20SPC100" || version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPC500PWE" || version == "V500R001C00SPH303" || version == "V500R001C00SPH508" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC100PWE" || version == "V500R001C20SPC101" || version == "V500R001C20SPC200" || version == "V500R001C20SPC200B062" || version == "V500R001C20SPC200PWE" || version == "V500R001C20SPC300B078" || version == "V500R001C20SPC300PWE" || version == "V500R001C30" || version == "V500R001C30SPC100" || version == "V500R001C30SPC100PWE" || version == "V500R001C30SPC200" || version == "V500R001C30SPC200PWE" || version == "V500R001C30SPC300" || version == "V500R001C50" || version == "V500R001C50PWE" || version == "V500R001C80" || version == "V500R001C80PWE" || version == "V500R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version == "V100R001C00SPC200" || version == "V100R001C10SPC200" || version == "V100R001C10SPC201" || version == "V100R001C20SPC100" || version == "V100R001C20SPC200" || version == "V500R001C00" || version == "V500R001C00SPC050" || version == "V500R001C00SPC090" || version == "V500R001C00SPC300" || version == "V500R001C00SPC500" || version == "V500R001C00SPC500PWE" || version == "V500R001C00SPH303" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC100PWE" || version == "V500R001C20SPC101" || version == "V500R001C20SPC200" || version == "V500R001C20SPC200PWE" || version == "V500R001C20SPC300" || version == "V500R001C20SPC300B078" || version == "V500R001C20SPC300PWE" || version == "V500R001C30" || version == "V500R001C30SPC100" || version == "V500R001C30SPC100PWE" || version == "V500R001C30SPC200" || version == "V500R001C30SPC200PWE" || version == "V500R001C30SPC300" || version == "V500R001C30SPC500" || version == "V500R001C30SPC600" || version == "V500R001C30SPC600PWE" || version == "V500R001C30SPC601" || version == "V500R001C50" || version == "V500R001C50PWE" || version == "V500R001C50SPC009" || version == "V500R001C50SPC100" || version == "V500R001C50SPC100PWE" || version == "V500R001C50SPC200" || version == "V500R001C50SPC200PWE" || version == "V500R001C50SPC300" || version == "V500R001C60" || version == "V500R001C60SPC100" || version == "V500R001C60SPC100PWE" || version == "V500R001C60SPC200" || version == "V500R001C60SPC200PWE" || version == "V500R001C60SPC300" || version == "V500R001C60SPC500" || version == "V500R001C80" || version == "V500R001C80PWE" || version == "V500R005C00" || version == "V500R005C00SPC100" || version == "V500R005C00SPC102") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6000v_firmware")  {
  if(version == "V500R001C10" || version == "V500R001C10SPC100" || version == "V500R001C10SPC200" || version == "V500R001C20" || version == "V500R001C20SPC100" || version == "V500R001C20SPC200" || version == "V500R001C20SPC300" || version == "V500R001C20SPC500" || version == "V500R001C20SPC600" || version == "V500R003C00" || version == "V500R003C00SPC100" || version == "V500R005C00" || version == "V500R005C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:espace_u1981_firmware")  {
  if(version == "V200R003C50SPC700") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003C50SPC900")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003C50SPC900");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
