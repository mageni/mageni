###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4284815)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813532");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-0978", "CVE-2018-1036", "CVE-2018-1040", "CVE-2018-8169",
                "CVE-2018-8205", "CVE-2018-8207", "CVE-2018-8210", "CVE-2018-8225",
                "CVE-2018-8249", "CVE-2018-8251", "CVE-2018-8267");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-13 09:16:31 +0530 (Wed, 13 Jun 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4284815)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4284815");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to errors,

  - When Internet Explorer improperly accesses objects in memory.

  - When the Windows kernel improperly handles objects in memory.

  - When Windows improperly handles objects in memory.

  - When the (Human Interface Device) HID Parser Library driver improperly handles
    objects in memory.

  - When NTFS improperly checks access.

  - In the way that the scripting engine handles objects in memory in Internet
    Explorer.

  - When Windows Media Foundation improperly handles objects in memory.

  - In Windows Domain Name System (DNS) DNSAPI.

  - In the way that the Windows Code Integrity Module performs hashing.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges, execute arbitrary code, install programs, view,
  change, or delete data or create new accounts with full user rights and create
  a denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4284815");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"winload.efi");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.19035"))
{
  report = report_fixed_ver(file_checked:sysPath + "\winload.efi",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.19035");
  security_message(data:report);
  exit(0);
}
exit(99);
