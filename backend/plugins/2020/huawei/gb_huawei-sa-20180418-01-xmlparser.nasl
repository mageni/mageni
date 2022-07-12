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
  script_oid("1.3.6.1.4.1.25623.1.0.108791");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Several Vulnerabilities in XMLparser Module of Huawei Products (huawei-sa-20180418-01-xmlparser)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There are two memory leak vulnerabilities in XMLparser module of Huawei products.");

  script_tag(name:"insight", value:"There are two memory leak vulnerabilities in XMLparser module of Huawei products. The vulnerability is due to incorrect handling of parameters. A local attacker could exploit this vulnerability by sending crafted parameters. A successful exploit could cause a memory leak and eventual denial of service (DoS) condition on an affected device. (Vulnerability ID: HWPSIRT-2017-04029 and HWPSIRT-2017-08243)There is a denial of service (DoS) vulnerability in XMLparser module of Huawei products. The vulnerability is due to lack of validation in XML document. A local attacker could exploit this vulnerability by crafting a malicious XML document. A successful exploit by the attacker could lead to resource exhaust and cause a DoS condition. (Vulnerability ID: HWPSIRT-2017-04030)There is a null pointer dereference vulnerability in XMLparser module of Huawei products. When the application dereferences a pointer that it expects to be valid, but is NULL. A local attacker could exploit this vulnerability by sending crafted parameters. A successful exploit could cause a denial of service and the process reboot. (Vulnerability ID: HWPSIRT-2017-04031)There are four out-of-bounds read vulnerabilities in XMLparser module of Huawei products. A local attacker may send crafted parameters in XML document to the affected products. Due to insufficient verification of the parameter, successful exploit will cause a DoS condition and the process reboot. (Vulnerability ID: HWPSIRT-2017-04032,HWPSIRT-2017-04074,HWPSIRT-2017-08244 and HWPSIRT-2017-08245)Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"By exploiting these vulnerabilities, an attacker can cause a memory leak and eventual denial of service (DoS) condition.");

  script_tag(name:"affected", value:"AR3200 versions V200R006C10 V200R006C11 V200R007C00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C30

DP300 versions V500R002C00

TE30 versions V600R006C00

TE40 versions V600R006C00

TE50 versions V600R006C00

TE60 versions V600R006C00

USG9500 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C30");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180418-01-xmlparser-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
