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
  script_oid("1.3.6.1.4.1.25623.1.0.108781");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-15323");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: DoS Vulnerability in Some Huawei Products (huawei-sa-20171202-01-pse)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a DoS vulnerability caused by memory exhaustion in some Huawei products.");

  script_tag(name:"insight", value:"There is a DoS vulnerability caused by memory exhaustion in some Huawei products. For insufficient input validation, attackers can craft and send some malformed messages to the target device to exhaust the memory of the device and cause a Denial of Service (DoS). (Vulnerability ID: HWPSIRT-2016-12104)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-15323.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to exhaust the memory of the device and cause a Denial of Service (DoS).");

  script_tag(name:"affected", value:"DBS3900 TDD LTE versions V100R003C00 V100R004C10

DP300 versions V500R002C00

NIP6600 versions V500R001C00 V500R001C20 V500R001C30

Secospace USG6500 versions V500R001C00 V500R001C20 V500R001C30

Secospace USG6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50SPC012T

TE60 versions V100R001C01SPC100 V100R001C10 V100R003C00 V500R002C00 V600R006C00

TP3106 versions V100R001C06B020 V100R002C00

VP9660 versions V200R001C02SPC100 V200R001C30SPC100 V500R002C00 V500R002C00SPC001T V500R002C00SPC200 V500R002C00SPC200T V500R002C00SPC201T V500R002C00SPC203T V500R002C00SPC204T V500R002C00SPC205T V500R002C00SPC206T V500R002C00SPC300 V500R002C00SPC400 V500R002C00SPC500 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC800 V500R002C00SPC900 V500R002C00SPC900T V500R002C00SPCa00 V500R002C00SPCb00 V500R002C00SPCb01T V500R002C00SPCc00 V500R002C00T V500R002C10

ViewPoint 8660 versions V100R008C03B013SP02 V100R008C03B013SP03 V100R008C03B013SP04 V100R008C03SPC100 V100R008C03SPC100B010 V100R008C03SPC100B011 V100R008C03SPC200 V100R008C03SPC200T V100R008C03SPC300 V100R008C03SPC400 V100R008C03SPC500 V100R008C03SPC600 V100R008C03SPC600T V100R008C03SPC700 V100R008C03SPC800 V100R008C03SPC900 V100R008C03SPCa00 V100R008C03SPCb00

ViewPoint 9030 versions V100R011C02SPC100 V100R011C03B012SP15

eCNS210_TD versions V100R004C10

eSpace U1981 versions V200R003C30SPC100");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171202-01-pse-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
