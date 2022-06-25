# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.818960");
  script_version("2022-01-14T07:06:50+0000");
  script_cve_id("CVE-2022-21840");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-01-14 11:23:55 +0000 (Fri, 14 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-13 09:31:05 +0530 (Thu, 13 Jan 2022)");
  script_name("Microsoft Excel 2013 RCE Vulnerability (KB5002128)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002128");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the presence of
  an error when a maliciously modified file is opened.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Excel 2013.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002128");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

vers = get_kb_item("SMB/Office/Excel/Version");
if(!vers){
  exit(0);
}

path = get_kb_item("SMB/Office/Excel/Install/Path");
if(!path){
  path = "Unable to fetch the install path";
}

if(version_in_range(version:vers, test_version:"15.0", test_version2:"15.0.5415.0999"))
{
  report = report_fixed_ver(file_checked:path + "Excel.exe",
                            file_version:vers, vulnerable_range:"15.0 - 15.0.5415.0999");
  security_message(data:report);
  exit(0);
}
exit(99);
