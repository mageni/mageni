###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4034665)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811605");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0174", "CVE-2017-0250", "CVE-2017-0293", "CVE-2017-8591",
                "CVE-2017-8593", "CVE-2017-8620", "CVE-2017-8624", "CVE-2017-8633",
                "CVE-2017-8635", "CVE-2017-8636", "CVE-2017-8641", "CVE-2017-8651",
                "CVE-2017-8653", "CVE-2017-8664", "CVE-2017-8666", "CVE-2017-8668");
  script_bugtraq_id(100038, 98100, 100039, 99430, 100032, 100034, 100061, 100069,
                    100055, 100056, 100057, 100058, 100059, 100085, 100089, 100092);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-09 08:53:58 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4034665)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4034665");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - The Win32k component fails to properly handle objects in memory.

  - Input Method Editor (IME) when IME improperly handles parameters in
    a method of a DCOM class.

  - When Microsoft browsers improperly access objects in memory.

  - When handling objects in memory in microsoft browsers.

  - When Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - Microsoft JET Database Engine that could allow remote code execution on an
    affected system.

  - When Windows Search handles objects in memory.

  - The way that Microsoft browser JavaScript engines render content when
    handling objects in memory.

  - When Internet Explorer improperly accesses objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  run arbitrary code in kernel mode, gain access to sensitive information and system
  functionality, also can gain the same user rights as the current user and obtain
  information to further compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4034665");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4034665");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\tdx.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.2.9200.22244"))
{
  report = 'File checked:     ' + sysPath + "\drivers\tdx.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 6.2.9200.22244\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
