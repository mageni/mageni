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
  script_oid("1.3.6.1.4.1.25623.1.0.143993");
  script_version("2020-05-27T09:21:02+0000");
  script_tag(name:"last_modification", value:"2020-05-27 09:21:02 +0000 (Wed, 27 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 08:54:30 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-17301");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VRP Data Communication: Weak Cryptography Vulnerability (huawei-sa-20171222-01-cryptography)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to a weak cryptography vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to not properly some values in the certificates, an unauthenticated
  remote attacker could forges a specific RSA certificate and exploits the vulnerability to pass identity
  authentication and logs into the target device to obtain permissions configured for the specific user name.");

  script_tag(name:"impact", value:"Successful exploit will cause the affected products to reset.");

  script_tag(name:"affected", value:"Huawei AR120-S, AR1200, AR1200-S, AR150, AR160, AR200, AR200-S,
  AR2200, AR2200-S, AR3200, AR3600, AR510, CloudEngine 12800, CloudEngine 5800, CloudEngine 6800,
  CloudEngine 7800, DP300, SMC2.0, SRG1300, SRG2300, SRG3300, TE30, TE60, VP9660, ViewPoint 8660,
  eSpace IAD, eSpace U1981 and eSpace USM.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171222-01-cryptography-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar120-s_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar200-s_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar1200-s_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar2200-s_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:ar510_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe =~ "^cpe:/o:huawei:ar(12|20|120|220)0-s_firmware") {
  if (version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" ||
      version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar1200_firmware") {
  if (version == "V200R005C20" || version == "V200R005C32" || version == "V200R006C10" ||
      version == "V200R007C00" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar150_firmware") {
  if (version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar160_firmware") {
  if (version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar200_firmware") {
  if (version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" ||
      version == "V200R007C01" || version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar2200_firmware") {
  if (version == "V200R005C20" || version == "V200R005C32" || version == "V200R006C10" ||
      version == "V200R007C00" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar3200_firmware") {
  if (version == "V200R005C32" || version == "V200R006C10" || version == "V200R006C11" ||
      version == "V200R007C00" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C00" || version == "V200R008C10" || version == "V200R008C20" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar3600_firmware") {
  if (version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar510_firmware") {
  if (version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" ||
      version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
