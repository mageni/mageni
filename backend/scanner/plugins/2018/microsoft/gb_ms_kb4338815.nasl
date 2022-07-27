###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4338815)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813652");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8282", "CVE-2018-0949", "CVE-2018-8206", "CVE-2018-8242",
                "CVE-2018-8287", "CVE-2018-8288", "CVE-2018-8291", "CVE-2018-8296",
                "CVE-2018-8304", "CVE-2018-8307", "CVE-2018-8308", "CVE-2018-8309",
                "CVE-2018-8313", "CVE-2018-8314", "CVE-2018-3665", "CVE-2018-3639",
                "CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754");
  script_bugtraq_id(104705);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-11 11:49:36 +0530 (Wed, 11 Jul 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4338815)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4338815");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists doe to error,

  - When Windows improperly handles File Transfer Protocol (FTP) connections.

  - When Windows Kernel API improperly enforces permissions.

  - When Windows improperly handles objects in memory.

  - When the Windows kernel fails to properly handle objects in memory.

  - When Microsoft WordPad improperly handles embedded OLE objects.

  - When the scripting engine handles objects in memory in Microsoft browsers.

  - When Windows fails a check, allowing a sandbox escape.

  - When the scripting engine handles objects in memory in Internet Explorer.

  - When Microsoft Internet Explorer improperly handles requests involving UNC
    resources.

  - When the Windows kernel-mode driver fails to properly handle objects in memory.

  - Due to Speculative execution side-channel vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a target system to stop responding, elevate their privilege level,
  run arbitrary code, bypass security, disclose sensitive information and also
  take control of an affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4338815");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.19064")){
  report = report_fixed_ver(file_checked:sysPath + "\Win32k.sys",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.19064");
  security_message(data:report);
  exit(0);
}

exit(99);
