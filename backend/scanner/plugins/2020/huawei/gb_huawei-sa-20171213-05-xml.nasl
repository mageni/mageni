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
  script_oid("1.3.6.1.4.1.25623.1.0.108787");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17330");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Memory Leak Vulnerability in Several Huawei Products (huawei-sa-20171213-05-xml)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a memory leak vulnerability in several Huawei products.");

  script_tag(name:"insight", value:"There is a memory leak vulnerability in several Huawei products. The software does not release allocated memory properly when parse XML element data. An authenticated attacker could upload a crafted XML file, successful exploit could cause the system service abnormal since run out of memory. (Vulnerability ID: HWPSIRT-2016-08074)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17330.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could cause the system service abnormal since run out of memory.");

  script_tag(name:"affected", value:"IPS Module versions V500R001C00B079 V500R001C00SPC200B085 V500R001C00SPC300B092 V500R001C00SPC500B098 V500R001C00SPC500B099 V500R001C00SPH303B001 V500R001C00SPH508B002 V500R001C20B031 V500R001C20SPC100B052 V500R001C20SPC100PWE V500R001C20SPC200B062 V500R001C20SPC200B063 V500R001C20SPC200PWE V500R001C30B027 V500R001C30B037

NGFW Module versions V500R002C00 V500R002C00B027

NIP6300 versions V500R001C00B079 V500R001C00SPC200B085 V500R001C00SPC300B092 V500R001C00SPC500B098 V500R001C00SPC500B099 V500R001C00SPH303B001 V500R001C00SPH508B002 V500R001C20B031 V500R001C20SPC100B052 V500R001C20SPC100PWE V500R001C20SPC200B062 V500R001C20SPC200B063 V500R001C20SPC200PWE V500R001C30B027 V500R001C30B037

NIP6600 versions V500R001C00B079 V500R001C00SPC200B085 V500R001C00SPC300B092 V500R001C00SPC500B098 V500R001C00SPC500B099 V500R001C00SPH303B001 V500R001C00SPH508B002 V500R001C20B031 V500R001C20SPC100B052 V500R001C20SPC100PWE V500R001C20SPC200B062 V500R001C20SPC200B063 V500R001C20SPC200PWE V500R001C30B027 V500R001C30B037

Secospace USG6300 versions V500R001C00B079 V500R001C00SPC200B085 V500R001C00SPC300B092 V500R001C00SPC500B098 V500R001C00SPC500B099 V500R001C00SPC500PWE V500R001C00SPH303B001 V500R001C00SPH508B002 V500R001C20B031 V500R001C20SPC100B052 V500R001C20SPC100PWE V500R001C20SPC101B053 V500R001C20SPC200B062 V500R001C20SPC200B063 V500R001C20SPC200PWE V500R001C30B027 V500R001C30B037

Secospace USG6500 versions V500R001C00B079 V500R001C00SPC200B085 V500R001C00SPC300B092 V500R001C00SPC500B098 V500R001C00SPC500B099 V500R001C00SPC500PWE V500R001C00SPH303B001 V500R001C00SPH508B002 V500R001C20B031 V500R001C20SPC100B052 V500R001C20SPC100PWE V500R001C20SPC200B062 V500R001C20SPC200B063 V500R001C20SPC200PWE V500R001C30B027 V500R001C30B037

Secospace USG6600 versions V500R001C00B063 V500R001C00B079 V500R001C00SPC100B080 V500R001C00SPC200B081 V500R001C00SPC200B082 V500R001C00SPC200B083 V500R001C00SPC200B085 V500R001C00SPC200B086 V500R001C00SPC300B087 V500R001C00SPC300B092 V500R001C00SPC301B950 V500R001C00SPC500B093 V500R001C00SPC500B098 V500R001C00SPC500B099 V500R001C00SPH303B001 V500R001C20B031 V500R001C20SPC100B051 V500R001C20SPC100B052 V500R001C20SPC101B053 V500R001C20SPC200B062 V500R001C20SPC200B063 V500R001C30B027

USG9500 versions V500R001C00B079 V500R001C00SPC200B085 V500R001C00SPC300B092 V500R001C00SPC303B002 V500R001C00SPC303B003 V500R001C00SPC500B098 V500R001C00SPC500B099 V500R001C00SPC500PWE V500R001C00SPC520T V500R001C00SPH303B001 V500R001C00SPH331T V500R001C00SPH508B002 V500R001C20B031 V500R001C20SPC100B052 V500R001C20SPC100PWE V500R001C20SPC101B053 V500R001C20SPC200B062 V500R001C20SPC200B063 V500R001C20SPC200PWE V500R001C20SPC205T V500R001C30B027 V500R001C30B037");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-05-xml-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
