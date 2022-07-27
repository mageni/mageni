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
  script_oid("1.3.6.1.4.1.25623.1.0.108795");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-1181", "CVE-2019-1182", "CVE-2019-1222", "CVE-2019-1226");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Four Remote Code Execution Vulnerability in Some Microsoft Windows Systems (huawei-sa-20190819-01-windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Microsoft released a security advisory to disclose four remote code execution vulnerabilities in Remote Desktop Services.");

  script_tag(name:"insight", value:"Microsoft released a security advisory to disclose four remote code execution vulnerabilities in Remote Desktop Services. An unauthenticated attacker connects to the target system using RDP and sends specially crafted requests to exploit the vulnerabilities. Successful exploit may cause arbitrary code execution on the target system. (Vulnerability ID: HWPSIRT-2019-08107,HWPSIRT-2019-08108,HWPSIRT-2019-08109 and HWPSIRT-2019-08110)The four vulnerabilities have been assigned four Common Vulnerabilities and Exposures (CVE) IDs: CVE-2019-1181, CVE-2019-1182, CVE-2019-1222 and CVE-2019-1226.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause arbitrary code execution on the target system.");

  script_tag(name:"affected", value:"2288H V5 versions V100R005C00

BH620 V2 versions V100R002C00

BH621 V2 versions V100R002C00

BH622 V2 versions V100R002C00

BH640 V2 versions V100R001C00

CH121 versions V100R001C00

CH140 versions V100R001C00

CH220 versions V100R001C00

CH221 versions V100R001C00

CH222 versions V100R002C00

CH240 versions V100R001C00

CH242 V3 versions V100R001C00

E6000 Chassis versions V100R001C00

Matebook, Magicbook series laptops versions Run the affected Windows operating system

OceanStor 18500 versions V100R001C30SPC200

OceanStor 18800 versions V100R001C30SPC200

OceanStor HVS85T versions V100R001C00

OceanStor HVS88T versions V100R001C00

RH1288 V2 versions V100R002C00

RH1288A V2 versions V100R002C00

RH2265 V2 versions V100R002C00

RH2268 V2 versions V100R002C00

RH2285 V2 versions V100R002C00

RH2285H V2 versions V100R002C00

RH2288 V2 versions V100R002C00

RH2288A V2 versions V100R002C00

RH2288E V2 versions V100R002C00

RH2288H V2 versions V100R002C00

RH2485 V2 versions V100R002C00

RH5885 V2 versions V100R001C00

RH5885 V3 versions V100R003C00

SMC2.0 versions V500R002C00 V600R006C00 V600R006C10 V600R019C00 V600R019C10

X6000 versions V100R002C00

X8000 versions V100R001C00

eSpace ECS versions V300R001C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190819-01-windows-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
