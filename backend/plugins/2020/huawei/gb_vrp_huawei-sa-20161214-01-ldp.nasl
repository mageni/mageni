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

CPE = "cpe:/o:huawei:cloudengine_12800_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143944");
  script_version("2020-05-20T05:19:53+0000");
  script_tag(name:"last_modification", value:"2020-05-22 09:10:29 +0000 (Fri, 22 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 04:30:31 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-8782");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VRP Data Communication: Memory Leak Vulnerability (huawei-sa-20161214-01-ldp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products are prone to a memory leak vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated attacker may send specific Label Distribution Protocol
  (LDP) packets to the devices repeatedly. Due to improper validation of some specific fields of the packet, the
  LDP processing module does not release the memory, resulting in memory leak.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to cause memory leak.");

  script_tag(name:"affected", value:"Huawei CloudEngine 12800.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161214-01-ldp-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork: TRUE))
  exit(0);

version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (version == "V100R003C00" || version == "V100R003C10" || version == "V100R005C00" || version == "V100R005C10" ||
    version == "V100R006C00") {
  report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00SPC700");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
