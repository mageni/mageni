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
  script_oid("1.3.6.1.4.1.25623.1.0.108796");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Algorithm Vulnerability in Some Huawei Products (huawei-sa-20190821-02-algorithm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a weak algorithm vulnerability in some Huawei products.");

  script_tag(name:"insight", value:"There is a weak algorithm vulnerability in some Huawei products. A remote, unauthenticated attacker may launch man-in-the-middle attack. Due to improper encryption mechanisms, an insecure encryption algorithm may be used, which may cause some information leak. (Vulnerability ID: HWPSIRT-2017-12132)Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause some information leak.");

  script_tag(name:"affected", value:"AR120-S versions V200R005C32 V200R006C10 V200R007C00 V200R008C20 V200R008C30 V200R008C50

AR1200 versions V200R005C30 V200R005C32 V200R006C10 V200R006C13 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30 V200R008C50

AR1200-S versions V200R005C30SPC200 V200R005C32 V200R006C10 V200R007C00 V200R008C20 V200R008C30 V200R008C50

AR150 versions V200R005C30SPC200 V200R005C32 V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30 V200R008C50

AR150-S versions V200R005C30SPC200 V200R005C32 V200R006C10SPC300 V200R007C00 V200R008C20 V200R008C30 V200R008C50

AR160 versions V200R005C30SPC200 V200R005C32 V200R006C10 V200R006C12 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30 V200R008C50

AR200 versions V200R005C30 V200R005C32 V200R006C10 V200R007C00 V200R007C01 V200R008C20 V200R008C30 V200R008C50

AR200-S versions V200R005C30SPC200 V200R005C32 V200R006C10 V200R007C00 V200R008C20 V200R008C30 V200R008C50

AR2200 versions V200R006C10 V200R006C13 V200R006C16PWE V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30 V200R008C50

AR2200-S versions V200R005C30SPC200 V200R005C32 V200R006C10 V200R007C00 V200R008C20 V200R008C30 V200R008C50

AR3200 versions V200R005C30 V200R005C31 V200R005C32 V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C30 V200R008C50

AR3600 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20 V200R008C50

AR510 versions V200R005C30SPC200 V200R005C32 V200R006C10 V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00SPC600 V200R008C20 V200R008C30 V200R008C50

CloudEngine 12800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC600 V200R002C50SPC800

CloudEngine 5800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC600 V200R002C50SPC800

CloudEngine 6800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC600 V200R002C50SPC800

CloudEngine 7800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC300 V100R005C10SPC200 V100R006C00SPC600 V200R001C00SPC600 V200R002C50SPC800

DP300 versions V500R002C00SPCb00

FusionSphere OpenStack versions V100R005C00SPC001 V100R005C10 V100R006C00RC1 V100R006C00RC1B055 V100R006C10 V100R006C10SPC301 V100R006C10SPC500 V100R006C10SPC600

NetEngine16EX versions V200R006C10 V200R007C00 V200R008C20 V200R008C30 V200R008C50

S12700 versions V200R007C00 V200R007C01B102 V200R008C00 V200R009C00SPC200 V200R010C00SPC300

S1700 versions V200R006C10SPC100 V200R009C00SPC500 V200R010C00SPC600

S2700 versions V200R006C00SPC300 V200R006C10SPC100 V200R007C00 V200R008C00SPC500 V200R009C00SPC200 V200R010C00SPC600

S5700 versions V200R005C02B020 V200R005C03B020 V200R006C00SPC100 V200R007C00 V200R008C00SPC500 V200R009C00SPC100 V200R010C00SPC300

S6700 versions V200R005C02B020 V200R008C00SPC500 V200R009C00SPC100 V200R010C00SPC300

S7700 versions V200R006C00SPC300 V200R007C00SPC100 V200R008C00SPC500 V200R009C00SPC100 V200R010C00

S9700 versions V200R006C00SPC300 V200R007C00SPC100 V200R007C01 V200R008C00 V200R009C00SPC100 V200R010C00

SRG1300 versions V200R005C32 V200R006C10SPC300 V200R007C00SPC900 V200R007C02 V200R008C20 V200R008C30 V200R008C50

SRG2300 versions V200R005C32 V200R006C10SPC300 V200R007C00SPC900 V200R007C02 V200R008C20 V200R008C30 V200R008C50

SRG3300 versions V200R005C32 V200R006C10SPC300 V200R007C00SPC900 V200R008C20 V200R008C30 V200R008C50

SoftCo versions V200R003C20SPCb00

TE60 versions V600R006C10

eSpace 8950 versions V200R003C00 V200R003C00SPC100

eSpace U1981 versions V100R001C20SPC700 V200R003C20SPCb00 V200R003C30SPC500 V200R003C50");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190821-02-algorithm-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
