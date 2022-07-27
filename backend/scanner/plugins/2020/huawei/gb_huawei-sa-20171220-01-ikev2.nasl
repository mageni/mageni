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
  script_oid("1.3.6.1.4.1.25623.1.0.108789");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17152", "CVE-2017-17153", "CVE-2017-17154", "CVE-2017-17155", "CVE-2017-17156", "CVE-2017-17157");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Multiple Security Vulnerabilities in the IKEv2 Protocol Implementation of Huawei Products (huawei-sa-20171220-01-ikev2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"IKEv2 has an out-of-bounds write vulnerability due to insufficient input validation.");

  script_tag(name:"insight", value:"IKEv2 has an out-of-bounds write vulnerability due to insufficient input validation. An attacker could exploit it to craft special packets to trigger out-of-bounds memory write, which may further lead to system exceptions. (Vulnerability ID: HWPSIRT-2017-03101)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17152.IKEv2 has a memory leak vulnerability due to memory release failure resulted from insufficient input validation. An attacker could exploit it to cause memory leak, which may further lead to system exceptions. (Vulnerability ID: HWPSIRT-2017-03102)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17153.IKEv2 has a DoS vulnerability due to insufficient input validation. An attacker could exploit it to cause unauthorized memory access, which may further lead to system exceptions. (Vulnerability ID: HWPSIRT-2017-03103)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17154.IKEv2 has an out-of-bounds memory access vulnerability due to incompliance with the 4-byte alignment requirement imposed by the MIPS CPU. An attacker could exploit it to cause unauthorized memory access, which may further lead to system exceptions. (Vulnerability ID: HWPSIRT-2017-03110)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17155.IKEv2 has an out-of-bounds memory access vulnerability due to insufficient input validation. An attacker could exploit it to craft special packets to trigger out-of-bounds memory access, which may further lead to system exceptions. (Vulnerability ID: HWPSIRT-2017-03111)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17156.IKEv2 has an out-of-bounds memory access vulnerability due to insufficient input validation. An attacker could exploit it to craft special packets to trigger out-of-bounds memory access, which may further lead to system exceptions. (Vulnerability ID: HWPSIRT-2017-03112)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17157.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker could exploit it to craft special packets to trigger out-of-bounds memory write, which may further lead to system exceptions.");

  script_tag(name:"affected", value:"DBS3900 TDD LTE versions V100R003C00 V100R004C10

IPS Module versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE

NGFW Module versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE

NIP6300 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE

NIP6600 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078

Secospace USG6300 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC101 V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE

Secospace USG6500 versions V500R001C00 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C00SPH508 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC101 V500R001C20SPC200 V500R001C20SPC200B062 V500R001C20SPC200PWE V500R001C20SPC300B078 V500R001C20SPC300PWE

Secospace USG6600 versions V500R001C00 V500R001C00SPC100 V500R001C00SPC200 V500R001C00SPC300 V500R001C00SPC301 V500R001C00SPC500 V500R001C00SPC500PWE V500R001C00SPH303 V500R001C20 V500R001C20SPC100 V500R001C20SPC100PWE V500R001C20SPC101 V500R001C20SPC200 V500R001C20SPC200PWE V500R001C20SPC300 V500R001C20SPC300B078 V500R001C20SPC300PWE

USG9500 versions V500R001C00 V500R001C20");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171220-01-ikev2-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
