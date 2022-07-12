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
  script_oid("1.3.6.1.4.1.25623.1.0.143977");
  script_version("2020-05-26T09:23:10+0000");
  script_tag(name:"last_modification", value:"2020-05-26 09:23:10 +0000 (Tue, 26 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 05:47:43 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17151");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VRP Data Communication: H323 Input Validation Vulnerability (huawei-sa-20171206-01-h323)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to an input validation vulnerability in
  the H323 protocol handling.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Since packet validation is insufficient, an unauthenticated attacker may
  send special H323 packets to exploit the vulnerability. Successful exploit could allow the attacker to send
  malicious packets and result in DOS attacks.");

  script_tag(name:"impact", value:"Successful exploit could allow the attacker to send malicious packets and
  result in DOS attacks.");

  script_tag(name:"affected", value:"Huawei AR100, AR100-S, AR110-S, AR120, AR120-S, AR1200, AR1200-S, AR150,
  AR150-S, AR160, AR200, AR200-S, AR2200, AR2200-S, AR3200, AR510, DP300, NetEngine16EX, RP200, SRG1300, SRG2300,
  SRG3300, TE30, TE40, TE50, TE60, TP3106, TP3206, ViewPoint 8660 and ViewPoint 9030.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-01-h323-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar100_firmware",
                     "cpe:/o:huawei:ar100-s_firmware",
                     "cpe:/o:huawei:ar110-s_firmware",
                     "cpe:/o:huawei:ar120_firmware",
                     "cpe:/o:huawei:ar120-s_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar150-s_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar200-s_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar1200-s_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar2200-s_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar510_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar100_firmware") {
  if (version == "V200R008C20SPC700" || version == "V200R008C20SPC700PWE" || version == "V200R008C20SPC800" ||
      version == "V200R008C20SPC800PWE" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar100-s_firmware") {
  if (version == "V200R007C00SPCA00" || version == "V200R007C00SPCB00" || version == "V200R008C20" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C20SPC800PWE" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar110-s_firmware") {
  if (version == "V200R007C00SPC600" || version == "V200R007C00SPC900" || version == "V200R007C00SPCB00" ||
      version == "V200R008C20SPC800" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar120_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10SPC300" || version == "V200R006C10SPC300PWE" ||
      version == "V200R007C00" || version == "V200R007C00PWE" || version == "V200R007C00SPC100" ||
      version == "V200R007C00SPC200" || version == "V200R007C00SPC600" || version == "V200R007C00SPC600PWE" ||
      version == "V200R007C00SPC900" || version == "V200R007C00SPC900PWE" || version == "V200R007C00SPCB00" ||
      version == "V200R007C00SPCB00PWE" || version == "V200R007C01" || version == "V200R008C20" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar120-s_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10SPC300" || version == "V200R007C00" ||
      version == "V200R007C00SPC100" || version == "V200R007C00SPC200" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC900" || version == "V200R007C00SPCA00" || version == "V200R007C00SPCB00" ||
      version == "V200R008C20" || version == "V200R008C20SPC700" || version == "V200R008C20SPC800" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar1200_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10PWE" || version == "V200R006C10SPC030" ||
      version == "V200R006C10SPC300" || version == "V200R006C10SPC300PWE" || version == "V200R006C10SPC600" ||
      version == "V200R006C13" || version == "V200R007C00" || version == "V200R007C00PWE" ||
      version == "V200R007C00SPC100" || version == "V200R007C00SPC200" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC600PWE" || version == "V200R007C00SPC900" || version == "V200R007C00SPC900PWE" ||
      version == "V200R007C00SPCA00" || version == "V200R007C00SPCB00" || version == "V200R007C00SPCB00PWE" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C20" ||
      version == "V200R008C20SPC600" || version == "V200R008C20SPC700" || version == "V200R008C20SPC800" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar1200-s_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10SPC300" || version == "V200R007C00" ||
      version == "V200R007C00SPC100" || version == "V200R007C00SPC200" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC900" || version == "V200R007C00SPCB00" || version == "V200R008C20" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C20SPC800PWE" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar150_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10PWE" || version == "V200R006C10SPC300" ||
      version == "V200R006C10SPC300PWE" || version == "V200R007C00" || version == "V200R007C00PWE" ||
      version == "V200R007C00SPC100" || version == "V200R007C00SPC200" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC600PWE" || version == "V200R007C00SPC900" || version == "V200R007C00SPC900PWE" ||
      version == "V200R007C00SPCB00" || version == "V200R007C00SPCB00PWE" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R007C02PWE" || version == "V200R008C20" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar150-s_firmware") {
  if (version == "V200R006C10SPC300" || version == "V200R007C00" || version == "V200R007C00SPC100" ||
      version == "V200R007C00SPC200" || version == "V200R007C00SPC600" || version == "V200R007C00SPC900" ||
      version == "V200R007C00SPCB00" || version == "V200R008C20" || version == "V200R008C20SPC700" ||
      version == "V200R008C20SPC800" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}


if (cpe == "cpe:/o:huawei:ar160_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10PWE" || version == "V200R006C10SPC100" ||
      version == "V200R006C10SPC200" || version == "V200R006C10SPC300" || version == "V200R006C10SPC300PWE" ||
      version == "V200R006C10SPC600" || version == "V200R006C12" || version == "V200R007C00" ||
      version == "V200R007C00PWE" || version == "V200R007C00SPC100" || version == "V200R007C00SPC200" ||
      version == "V200R007C00SPC500" || version == "V200R007C00SPC600" || version == "V200R007C00SPC600PWE" ||
      version == "V200R007C00SPC900" || version == "V200R007C00SPC900PWE" || version == "V200R007C00SPCB00" ||
      version == "V200R007C00SPCB00PWE" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C20" || version == "V200R008C20SPC500T" || version == "V200R008C20SPC501T" ||
      version == "V200R008C20SPC600" || version == "V200R008C20SPC700" || version == "V200R008C20SPC800" ||
      version == "V200R008C30" || version == "V200R008C30SPC100") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar200_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10PWE" || version == "V200R006C10SPC100" ||
      version == "V200R006C10SPC300" || version == "V200R006C10SPC300PWE" || version == "V200R007C00" ||
      version == "V200R007C00PWE" || version == "V200R007C00SPC100" || version == "V200R007C00SPC200" ||
      version == "V200R007C00SPC600" || version == "V200R007C00SPC600PWE" || version == "V200R007C00SPC900" ||
      version == "V200R007C00SPC900PWE" || version == "V200R007C00SPCB00" || version == "V200R007C00SPCB00PWE" ||
      version == "V200R007C01" || version == "V200R008C20" || version == "V200R008C20SPC600" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C20SPC900" ||
      version == "V200R008C20SPC900PWE" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar200-s_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10SPC300" || version == "V200R007C00" ||
      version == "V200R007C00SPC100" || version == "V200R007C00SPC200" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC900" || version == "V200R007C00SPCB00" || version == "V200R008C20" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar2200_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10PWE" || version == "V200R006C10SPC300" ||
      version == "V200R006C10SPC300PWE" || version == "V200R006C10SPC600" || version == "V200R006C13" ||
      version == "V200R006C16PWE" || version == "V200R007C00" || version == "V200R007C00PWE" ||
      version == "V200R007C00SPC100" || version == "V200R007C00SPC200" || version == "V200R007C00SPC500" ||
      version == "V200R007C00SPC600" || version == "V200R007C00SPC600PWE" || version == "V200R007C00SPC900" ||
      version == "V200R007C00SPC900PWE" || version == "V200R007C00SPCA00" || version == "V200R007C00SPCB00" ||
      version == "V200R007C00SPCB00PWE" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C20" || version == "V200R008C20SPC600" || version == "V200R008C20SPC700" ||
      version == "V200R008C20SPC800" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar2200-s_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10SPC300" || version == "V200R007C00" ||
      version == "V200R007C00SPC100" || version == "V200R007C00SPC200" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC900" || version == "V200R007C00SPCB00" || version == "V200R008C20" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C20SPC800PWE" ||
      version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}


if (cpe == "cpe:/o:huawei:ar3200_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10PWE" || version == "V200R006C10SPC100" ||
      version == "V200R006C10SPC200" || version == "V200R006C10SPC300" || version == "V200R006C10SPC300PWE" ||
      version == "V200R006C10SPC600" || version == "V200R006C11" || version == "V200R007C00" ||
      version == "V200R007C00PWE" || version == "V200R007C00SPC100" || version == "V200R007C00SPC200" ||
      version == "V200R007C00SPC200" || version == "V200R007C00SPC200" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC600PWE" || version == "V200R007C00SPC900" || version == "V200R007C00SPC900PWE" ||
      version == "V200R007C00SPCA00" || version == "V200R007C00SPCB00" || version == "V200R007C00SPCB00PWE" ||
      version == "V200R007C00SPCC00" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C00" || version == "V200R008C10" || version == "V200R008C20" ||
      version == "V200R008C20B560" || version == "V200R008C20B570" || version == "V200R008C20B580" ||
      version == "V200R008C20SPC700" || version == "V200R008C20SPC800" || version == "V200R008C30" ||
      version == "V200R008C30B010" || version == "V200R008C30B020" || version == "V200R008C30B030" ||
      version == "V200R008C30B050" || version == "V200R008C30B060" || version == "V200R008C30B070" ||
      version == "V200R008C30B080" || version == "V200R008C30SPC067T") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:ar510_firmware") {
  if (version == "V200R006C10" || version == "V200R006C10PWE" || version == "V200R006C10SPC200" ||
      version == "V200R006C12" || version == "V200R006C13" || version == "V200R006C15" ||
      version == "V200R006C16" || version == "V200R006C17" || version == "V200R007C00SPC180T" ||
      version == "V200R007C00SPC600" || version == "V200R007C00SPC900" || version == "V200R007C00SPCB00" ||
      version == "V200R008C20" || version == "V200R008C30") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
