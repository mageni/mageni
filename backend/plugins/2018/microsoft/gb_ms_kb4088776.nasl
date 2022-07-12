###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4088776)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812833");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2018-0811", "CVE-2018-0813", "CVE-2018-0814", "CVE-2018-0886",
   	        "CVE-2018-0888", "CVE-2018-0889", "CVE-2018-0891", "CVE-2018-0893",
		"CVE-2018-0894", "CVE-2018-0895", "CVE-2018-0896", "CVE-2018-0897",
 		"CVE-2018-0898", "CVE-2018-0899", "CVE-2018-0900", "CVE-2018-0901",
		"CVE-2018-0902", "CVE-2018-0904", "CVE-2018-0926", "CVE-2018-0927",
		"CVE-2018-0929", "CVE-2018-0930", "CVE-2018-0931", "CVE-2018-0932",
   		"CVE-2018-0933", "CVE-2018-0934", "CVE-2018-0935", "CVE-2018-0936",
		"CVE-2018-0937", "CVE-2018-0939", "CVE-2018-0977", "CVE-2018-0983",
		"CVE-2018-0816", "CVE-2018-0817", "CVE-2018-0868", "CVE-2018-0872",
 		"CVE-2018-0873", "CVE-2018-0874", "CVE-2018-0876", "CVE-2018-0877",
                "CVE-2018-0878", "CVE-2018-0879", "CVE-2018-0880", "CVE-2018-0881",
		 "CVE-2018-0883", "CVE-2018-0884", "CVE-2018-0885", "CVE-2018-0771");
  script_bugtraq_id(103232, 103250, 103251, 103265, 103262, 103295, 103309, 103288,
                    103231, 103238, 103240, 103241, 103242, 103243, 103244, 103245,
                    103266, 103246, 103247, 103310, 103299, 103272, 103273, 103307,
                    103274, 103275, 103298, 103270, 103271, 103305, 103380, 103381,
		    103248, 103249, 103236, 103267, 103268, 103269, 103289, 103227,
                    103230, 103303, 103239, 103256, 103259, 103260, 103261, 102857);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-14 10:01:51 +0530 (Wed, 14 Mar 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4088776)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4088776");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - The way that the scripting engine handles objects in memory in Microsoft
    Edge and Internet Explorer.

  - Windows Hyper-V on a host operating system fails to properly validate
    input from an authenticated user or privileged user on a guest operating system.

  - The way that the Windows Graphics Device Interface (GDI) handles objects in
    memory.

  - Windows Scripting Host which could allow an attacker to bypass Device
    Guard.

  - The Credential Security Support Provider protocol (CredSSP).

  - Windows kernel-mode driver fails to properly handle
    objects in memory.

  - Desktop Bridge does not properly manage the virtual registry.

  - Windows when the Microsoft Video Control mishandles objects in memory.

  - Windows Shell does not properly validate file copy destinations.

  - Storage Services improperly handles objects in memory.

  - Kernel Address Space Layout Randomization (ASLR) bypass error.

  - Windows Installer fails to properly sanitize input leading to an insecure
    library loading behavior.

  - Microsoft Edge improperly handles requests of different origins.

  - Desktop Bridge VFS does not take into acccount user/kernel
    mode when managing file paths.

  - Windows Remote Assistance incorrectly processes XML External Entities
    (XXE).");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to information, crash server and run arbitrary code in system
  mode.");

  script_tag(name:"affected", value:"Windows 10 Version 1709 for 32-bit Systems,

  Windows 10 Version 1709 for 64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4088776");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.16299.0", test_version2:"11.0.16299.308"))
{
  report = report_fixed_ver(file_checked:sysPath + "\edgehtml.dll",
  file_version:edgeVer, vulnerable_range:"11.0.16299.0 - 11.0.16299.308");
  security_message(data:report);
  exit(0);
}
exit(0);
