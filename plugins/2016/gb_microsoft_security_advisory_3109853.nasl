###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft TLS Session Resumption Interoperability Improvement Advisory (3109853)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806662");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-01-14 11:12:27 +0530 (Thu, 14 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft TLS Session Resumption Interoperability Improvement Advisory (3109853)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (3109853).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An update is available that improve
  interoperability between Schannel-based TLS clients and 3rd-party TLS servers
  that enable RFC5077-based resumption and that send the NewSessionTicket message
  in the abbreviated TLS handshake.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to perform a fallback to a lower TLS protocol version than the one
  that would have been negotiated and conduct further attacks.");

  script_tag(name:"affected", value:"Windows Server 2012 R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 8 x32/x64
  Microsoft Windows Server 2012
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3109853");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/3109853");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\schannel.dll");
dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"SysWOW64\schannel.dll");
if(dllVer1){
  schpPath64 = sysPath + "\SysWOW64\schannel.dll";
}

if(!dllVer && !dllVer1){
  exit(0);
}

if(hotfix_check_sp(win8:1) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17592"))
  {
    Vulnerable_range = "Version Less than - 6.2.9200.17592";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21707"))
  {
    Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21707";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8x64:1, win2012:1) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"6.2.9200.17590"))
  {
    report = 'File checked:     ' + schpPath64 + '\n' +
             'File version:     ' + dllVer1  + '\n' +
             'Vulnerable range:  Less than 6.2.9200.17590\n' ;
    security_message(data:report);
    exit(0);
  }
  else if(version_in_range(version:dllVer1, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21707"))
  {
    report = 'File checked:     ' + schpPath64 + '\n' +
             'File version:     ' + dllVer1  + '\n' +
             '6.2.9200.21000 - 6.2.9200.21707\n' ;
    security_message(data:report);
    exit(0);
  }
}

## Win 8.1 and 2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.18154"))
  {
    Vulnerable_range = "Version Less than - 6.3.9600.18154";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"10.0.10240.16644"))
  {
    Vulnerable_range = "Less than 10.0.10240.16644";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.62"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.62";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\schannel.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
