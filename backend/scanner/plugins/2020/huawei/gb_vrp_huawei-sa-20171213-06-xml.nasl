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
  script_oid("1.3.6.1.4.1.25623.1.0.143986");
  script_version("2020-05-27T07:48:04+0000");
  script_tag(name:"last_modification", value:"2020-05-27 07:48:04 +0000 (Wed, 27 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 04:50:18 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17291", "CVE-2017-17292", "CVE-2017-17293", "CVE-2017-17294");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VRP Data Communication: Multiple Vulnerabilities (huawei-sa-20171213-06-xml)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Huawei products are prone multiple vulnerabilities:

  - Memory leak vulnerability (CVE-2017-17291)

  - Denial of service vulnerability (CVE-2017-17292)

  - Buffer overflow vulnerability (CVE-2017-17293)

  - Null pointer dereference vulnerability (CVE-2017-17294)");

  script_tag(name:"impact", value:"Successful exploit will result in memory leak or cause some service abnormal.");

  script_tag(name:"affected", value:"Huawei AR120-S, AR1200, AR1200-S, AR150, AR150-S, AR160, AR200, AR200-S,
  AR2200, AR2200-S, AR3200, AR3600, AR510, DP300, MAX PRESENCE, NetEngine16EX, RP200, SRG1300, SRG2300,
  SRG3300, TE30, TE40, TE50, TE60, TP3106 and TP3206.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-06-xml-en");

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
                     "cpe:/o:huawei:ar510_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe =~ "^cpe:/o:huawei:ar(12|120|15|20|220)0-s_firmware") {
  if (version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar1200_firmware") {
  if (version == "V200R006C10" || version == "V200R006C13" || version == "V200R007C00" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C20" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar150_firmware") {
  if (version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar160_firmware") {
  if (version == "V200R006C10" || version == "V200R006C12" || version == "V200R007C00" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C20" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar200_firmware") {
  if (version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R008C20" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar2200_firmware") {
  if (version == "V200R006C10" || version == "V200R006C13" || version == "V200R006C16" ||
      version == "V200R007C00" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C20" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar3200_firmware") {
  if (version == "V200R006C10" || version == "V200R006C11" || version == "V200R007C00" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C00" ||
      version == "V200R008C10" || version == "V200R008C20" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar3600_firmware") {
  if (version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C00" ||
      version == "V200R008C20") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar510_firmware") {
  if (version == "V200R006C10" || version == "V200R006C12" || version == "V200R006C13" ||
      version == "V200R006C15" || version == "V200R006C16" || version == "V200R006C17" ||
      version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
