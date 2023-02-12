# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826754");
  script_version("2023-01-11T10:12:37+0000");
  script_cve_id("CVE-2021-21999");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-30 00:34:00 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"creation_date", value:"2023-01-10 15:43:23 +0530 (Tue, 10 Jan 2023)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Tools Privilege Escalation Vulnerability - VMSA-2021-0013 (Windows)");

  script_tag(name:"summary", value:"VMware Tools is prone to a local privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to local privilege escalation
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  with normal access to a virtual machine can execute code with elevated privileges.");

  script_tag(name:"affected", value:"VMware Tools 11.x.y prior to 11.2.6 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Tool version 11.2.6 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2021-0013.html");
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_tools_detect_win.nasl");
  script_mandatory_keys("VMwareTools/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
if(!vers = infos['version']){
  exit(0);
}
path = infos['location'];

if(vers =~ "^11\." && version_is_less(version:vers, test_version:"11.2.6"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.2.6", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
