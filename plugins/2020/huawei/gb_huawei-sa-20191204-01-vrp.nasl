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
  script_oid("1.3.6.1.4.1.25623.1.0.108800");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Algorithm Vulnerability in Huawei VRP Platform (huawei-sa-20191204-01-vrp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a weak algorithm vulnerability in Huawei VRP platform.");

  script_tag(name:"insight", value:"There is a weak algorithm vulnerability in Huawei VRP platform. These products use SSH to ensure transmission security, but the SSH algorithm suite includes weak algorithms, such as AES128-CBC, AES256-CBC, and 3DES-CBC while these weak algorithms is enable by default. Attackers may exploit the weak algorithm vulnerability to crack the cipher text and cause confidential information leaks on the transmission links. (Vulnerability ID: HWPSIRT-2019-02008)Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Attackers may exploit the vulnerability to crack the encryption algorithm and cause confidential information leaks on the transmission links.");

  script_tag(name:"affected", value:"S12700 versions V200R007C00 V200R007C01 V200R007C20 V200R008C00 V200R010C00 V200R011C10 V200R012C00

S1700 versions V200R006C10 V200R010C00 V200R011C10 V200R012C00 V200R012C20

S2700 versions V200R006C00 V200R006C10 V200R007C00 V200R008C00 V200R010C00 V200R011C00 V200R011C10 V200R012C00

S5700 versions V200R005C00 V200R005C02 V200R005C03 V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C00 V200R011C10 V200R012C00 V200R012C20

S6700 versions V200R005C00 V200R005C01 V200R005C02 V200R008C00 V200R010C00 V200R011C00 V200R011C10 V200R012C00

S7700 versions V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00

S9700 versions V200R006C00 V200R007C00 V200R007C01 V200R008C00 V200R010C00 V200R011C10 V200R012C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191204-01-vrp-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
