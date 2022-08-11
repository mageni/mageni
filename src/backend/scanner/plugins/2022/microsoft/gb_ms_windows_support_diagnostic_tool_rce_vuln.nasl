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
  script_oid("1.3.6.1.4.1.25623.1.0.821253");
  script_version("2022-06-01T13:00:54+0000");
  script_cve_id("CVE-2022-30190");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-06-02 06:59:17 +0000 (Thu, 02 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-01 11:37:17 +0530 (Wed, 01 Jun 2022)");
  script_name("Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Update released for Microsoft Windows
  Support Diagnostic Tool (MSDT) dated 30-05-2022");

  script_tag(name:"vuldetect", value:"Checks if the required workaround is missing in
  target host.");

  script_tag(name:"insight", value:"The flaw exists due to the way MSDT is called
  using the URL protocol from certain applications such as Word.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code with the privileges of the calling application.
  The attacker can then install programs, view, change, or delete data, or create
  new accounts in the context allowed by the user's rights.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2019

  - Microsoft Windows Server 2016

  - Microsoft Windows 7 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 x32

  - Microsoft Windows Server 2008 R2 x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 11

  - Microsoft Windows Server 2022

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1809/1607/21H1/20H2/21H2 x32/x64");

  script_tag(name:"solution", value:"The vendor has released workaround. Please see the references for more information.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-30190");
  script_xref(name:"URL", value:"https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}
include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1,win2012:1, win2012R2:1,
                   win10:1, win10x64:1, win2016:1, win2008:3, win2019:1) <= 0){
  exit(0);
}

key = "ms-msdt";
if(!registry_key_exists(key:key, type:"HKCR")){
  exit(0);
}else{
   ## Microsoft recommends disabling the MSDT URL protocol
   ## It is not yet clear what the impact of disabling this may be
   report = report_fixed_ver(installed_version:"Microsoft Windows Support Diagnostic Tool (MSDT)", fixed_version:"Apply the Workaround");
   security_message(data:report);
   exit(0);
}

exit(99);
