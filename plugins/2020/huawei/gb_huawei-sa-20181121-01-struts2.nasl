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
  script_oid("1.3.6.1.4.1.25623.1.0.108792");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-11776");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Apache Struts2 S2-057 Remote Code Execution Vulnerability in Some Huawei Products (huawei-sa-20181121-01-struts2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"It is possible to perform a RCE attack when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then namespace value isn't set for a result defined in underlying configurations and in same time, its upper package configuration have no or wildcard namespace and same possibility when using url tag which doesn't have value and action set and in same time, its upper package configuration have no or wildcard namespace.");

  script_tag(name:"insight", value:"It is possible to perform a RCE attack when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then namespace value isn't set for a result defined in underlying configurations and in same time, its upper package configuration have no or wildcard namespace and same possibility when using url tag which doesn't have value and action set and in same time, its upper package configuration have no or wildcard namespace. (Vulnerability ID: HWPSIRT-2018-08200)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2018-11776.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability to perform a remote code execution attack");

  script_tag(name:"affected", value:"Seco VSM versions V200R002C00

eLog versions V200R005C00 V200R006C10 V200R007C00SPC100");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20181121-01-struts2-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
