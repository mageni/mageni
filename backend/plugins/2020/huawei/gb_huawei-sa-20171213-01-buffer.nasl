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
  script_oid("1.3.6.1.4.1.25623.1.0.108785");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-15350");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Buffer Overflow Vulnerability in Some Huawei Products (huawei-sa-20171213-01-buffer)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a buffer overflow vulnerability in the Common Open Policy Service Protocol (COPS) module of some Huawei products.");

  script_tag(name:"insight", value:"There is a buffer overflow vulnerability in the Common Open Policy Service Protocol (COPS) module of some Huawei products. An unauthenticated, remote attacker could exploit this vulnerability by sending specially crafted message to the affected products. The vulnerability is due to insufficient input validation of the message, which could result in a buffer overflow. Successful exploit may cause some services abnormal. (Vulnerability ID: HWPSIRT-2017-04072)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-15350.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause some service abnormal.");

  script_tag(name:"affected", value:"DP300 versions V500R002C00

IPS Module versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

NGFW Module versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30 V500R001C00 V500R001C20 V500R002C00 V500R002C10

NIP6300 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

NIP6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

NIP6800 versions V500R001C50

RP200 versions V500R002C00SPC200 V600R006C00

SeMG9811 versions V300R001C01SPC500

Secospace USG6300 versions V100R001C10SPC200 V100R001C20SPC002T V100R001C30B018 V500R001C00 V500R001C20 V500R001C30 V500R001C50

Secospace USG6500 versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30B018 V500R001C00 V500R001C20 V500R001C30 V500R001C50

Secospace USG6600 versions V100R001C00SPC200 V100R001C20SPC070B710 V100R001C30 V500R001C00 V500R001C00 V500R001C20 V500R001C20 V500R001C30 V500R001C30 V500R001C50 V500R001C50

TE30 versions V100R001C02B053SP02 V100R001C10 V500R002C00SPC200 V600R006C00

TE40 versions V500R002C00SPC600 V600R006C00

TE50 versions V500R002C00SPC600 V600R006C00

TE60 versions V100R001C01SPC100 V100R001C10 V500R002C00 V600R006C00

TP3206 versions V100R002C00 V100R002C10

USG9500 versions V500R001C00 V500R001C30 V500R001C30SPC109T V500R001C30SPC115T V500R001C30SPC117T V500R001C30SPC122T V500R001C30SPC123T V500R001C30SPC211T V500R001C30SPC215T V500R001C50 V500R001C50SPC005T V500R001C50SPC020T V500R001C50SPC030T");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-01-buffer-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
