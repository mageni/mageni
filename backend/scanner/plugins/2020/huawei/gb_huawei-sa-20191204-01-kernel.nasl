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
  script_oid("1.3.6.1.4.1.25623.1.0.108799");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-11477");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Integer Overflow Vulnerability in the Linux Kernel (SACK Panic) (huawei-sa-20191204-01-kernel)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Jonathan Looney discovered that the TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an integer overflow in the Linux kernel when handling TCP Selective Acknowledgments (SACKs).");

  script_tag(name:"insight", value:"Jonathan Looney discovered that the TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an integer overflow in the Linux kernel when handling TCP Selective Acknowledgments (SACKs). A remote attacker could use this to cause a denial of service. (Vulnerability ID: HWPSIRT-2019-06130)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-11477.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"A remote attacker could use this vulnerability to cause a denial of service.");

  script_tag(name:"affected", value:"AC6605 versions V200R009C00 V200R010C00

B525s-23a versions Versions earlier than TCPU-V800R001B191D27SP00C00 Versions earlier than TCPU-V800R001B191D27SP00C00 Versions earlier than TCPU-V800R001B191D27SP00C00 Versions earlier than TCPU-V800R001B191D27SP00C00

Florida-L21 versions Versions earlier than 9.1.0.115(C432E5R1P1T8) Versions earlier than 9.1.0.120(C185E5R1P4T8)

Florida-L22 versions Versions earlier than 9.1.0.120(C636E5R1P1T8)

Florida-L23 versions Versions earlier than 9.1.0.121(C605E5R1P1T8)

FusionSphere OpenStack versions V100R006C00RC1 V100R006C00U1 V100R006C10 V100R006C10RC1B060 V100R006C10SPC002B010 V100R006C10SPC110 V100R006C10SPC200B030 V100R006C10SPC500 V100R006C10SPC600

HUAWEI 4G Router 2 versions Versions earlier than 10.0.1.1(H187SP15C00)

Honor 8A versions Versions earlier than 9.1.0.234(C636E4R3P1) Versions earlier than 9.1.0.234(C636E4R4P1) Versions earlier than 9.1.0.234(C636E4R4P1) Versions earlier than 9.1.0.234(C636E4R4P1)

Leland-AL10B versions Versions earlier than 9.1.0.113(C00E111R2P10T8)

Leland-L21A versions Versions earlier than 9.1.0.118(C185E4R1P4T8)

Leland-L22C versions Versions earlier than 9.1.0.118(C636E4R1P1T8)

Leland-L31A versions Versions earlier than 9.1.0.121(C432E4R1P3T8)

OceanStor 5300 V3 versions V300R006C50SPC100 V300R006C60

OceanStor 5500 V3 versions V300R006C50SPC100 V300R006C60

OceanStor 5600 V3 versions V300R006C50SPC100 V300R006C60

OceanStor 5800 V3 versions V300R006C50SPC100 V300R006C60

OceanStor 6800 V3 versions V300R006C50SPC100 V300R006C60

OceanStor 9000 versions V300R006C00SPC001 V300R006C10

iManager NetEco 6000 versions V600R008C00 V600R008C10SPC300 V600R008C20");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191204-01-kernel-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
