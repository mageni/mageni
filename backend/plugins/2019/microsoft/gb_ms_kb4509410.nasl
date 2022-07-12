# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815516");
  script_version("2019-07-10T14:00:44+0000");
  script_cve_id("CVE-2019-1136", "CVE-2019-1084");
  script_bugtraq_id(109030, 108929);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-07-10 14:00:44 +0000 (Wed, 10 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-10 09:35:44 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft Exchange Server Multiple Vulnerabilities (KB4509410)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4509410.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error when Exchange allows creation of entities with Display Names having
    non-printable characters.

  - An elevation of privilege error in Microsoft Exchange Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain the same rights as any other user of the Exchange server and gain access
  to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft Exchange Server 2010 Service Pack 3");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4509410");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_exchange_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Exchange/Server/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exchangePath = get_app_location(cpe:CPE);
if(!exchangePath|| "Could not find the install location" >< exchangePath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Bin\ExSetup.exe");
if(!exeVer){
  exit(0);
}

if(exeVer =~ "^14\." && version_is_less(version:exeVer, test_version:"14.3.468"))
{
  report = report_fixed_ver(file_checked:exchangePath + "Bin\ExSetup.exe",
                            file_version:exeVer, vulnerable_range:"14.0 - 14.3.467");
  security_message(data:report);
  exit(0);
}
exit(99);
