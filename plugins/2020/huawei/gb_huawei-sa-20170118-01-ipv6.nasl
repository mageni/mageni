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
  script_oid("1.3.6.1.4.1.25623.1.0.108770");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-1409");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability (huawei-sa-20170118-01-ipv6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a vulnerability in the IP Version 6 (IPv6) Neighbor Discovery packet process of multiple products.");

  script_tag(name:"insight", value:"There is a vulnerability in the IP Version 6 (IPv6) Neighbor Discovery packet process of multiple products, successful exploit could allow an unauthenticated, remote attacker to cause an affected device to start dropping legitimate IPv6 neighbors as legitimate ND times out, leading to a denial of service (DoS). (Vulnerability ID: HWPSIRT-2016-06012)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-1409.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could allow an unauthenticated, remote attacker to cause an affected device to start dropping legitimate IPv6 neighbors as legitimate ND times out, leading to DOS.");

  script_tag(name:"affected", value:"AR120& AR150& AR160& AR200& AR500& AR510& AR1200& AR2200& AR3200& AR3600 versions V200R005C00 V200R006C00 V200R006C10 V200R007C00

CloudEngine 12800 versions V100R001C00 V100R001C01 V100R002C00 V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00

CloudEngine 5800 versions V100R001C00 V100R001C01 V100R002C00 V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00

CloudEngine 6800 versions V100R001C00 V100R001C01 V100R002C00 V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00

CloudEngine 7800 versions V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00

CloudEngine 8800 versions V100R006C00

S12700 versions V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S2300 versions V100R006C05

S2700 versions V100R006C05

S3300 versions V100R006C05

S3700 versions V100R006C05

S5300 versions V200R002C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S5700 versions V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S6300 versions V200R002C00 V200R003C00 V200R005C00 V200R007C00 V200R008C00 V200R009C00

S6700 versions V200R002C00 V200R003C00 V200R005C00 V200R007C00 V200R008C00 V200R009C00

S7700 versions V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S9300 versions V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00

S9700 versions V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R009C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170118-01-ipv6-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
