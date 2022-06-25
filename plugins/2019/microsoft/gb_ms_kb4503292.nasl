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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815208");
  script_version("2019-06-12T13:47:22+0000");
  script_cve_id("CVE-2017-8533", "CVE-2019-0713", "CVE-2019-0722", "CVE-2019-0888",
                "CVE-2019-0904", "CVE-2019-0905", "CVE-2019-0906", "CVE-2019-0907",
                "CVE-2019-0908", "CVE-2019-0909", "CVE-2019-0920", "CVE-2019-0941",
                "CVE-2019-0943", "CVE-2019-0948", "CVE-2019-0960", "CVE-2019-0968",
                "CVE-2019-0972", "CVE-2019-0973", "CVE-2019-0974", "CVE-2019-0977",
                "CVE-2019-0984", "CVE-2019-0985", "CVE-2019-0986", "CVE-2019-0988",
                "CVE-2019-1005", "CVE-2019-1009", "CVE-2019-1010", "CVE-2019-1011",
                "CVE-2019-1012", "CVE-2019-1013", "CVE-2019-1014", "CVE-2019-1015",
                "CVE-2019-1016", "CVE-2019-1017", "CVE-2019-1019", "CVE-2019-1025",
                "CVE-2019-1028", "CVE-2019-1038", "CVE-2019-1039", "CVE-2019-1040",
                "CVE-2019-1043", "CVE-2019-1045", "CVE-2019-1046", "CVE-2019-1047",
                "CVE-2019-1048", "CVE-2019-1049", "CVE-2019-1053", "CVE-2019-1055",
                "CVE-2019-1080", "CVE-2019-1081");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-12 13:47:22 +0000 (Wed, 12 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-12 11:02:18 +0530 (Wed, 12 Jun 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4503292)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4503292");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Windows Event Viewer (eventvwr.msc) improperly parses XML input
    containing a reference to an external entity.

  - Microsoft Hyper-V on a host server fails to properly validate input from
    a privileged user on a guest operating system.

  - Microsoft Speech API (SAPI) improperly handles text-to-speech (TTS) input.

  - Windows GDI component improperly discloses the contents of its
    memory.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code, elevate privileges by escaping a
  sandbox, gain access to sensitive information, run processes and
  delete files and folders in an elevated context.");

  script_tag(name:"affected", value:"Windows 7 for 32-bit/x64 Systems Service Pack 1

  Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4503292/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Ntdll.dll");
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"6.1.7601.24475"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Ntdll.dll",
                            file_version:dllVer, vulnerable_range:"Less than 6.1.7601.24475");
  security_message(data:report);
  exit(0);
}
exit(99);
