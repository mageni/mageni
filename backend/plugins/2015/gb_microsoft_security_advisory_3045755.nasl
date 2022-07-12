###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Update To Improve PKU2U Authentication Security Advisory (3045755)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805451");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-04-17 16:49:36 +0530 (Fri, 17 Apr 2015)");
  script_name("Microsoft Update To Improve PKU2U Authentication Security Advisory (3045755)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (3045755)");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate update is applied or not.");

  script_tag(name:"insight", value:"An update is available that improves the
  authentication used by the Public Key Cryptography User-to-User (PKU2U)
  security support provider (SSP)");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to break certain authentication scenarios.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012 R2

  Microsoft Windows 8.1 x32/x64 Edition");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://support.microsoft.com/en-us/kb/3045755");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/3045755");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Pku2u.dll");
if(!dllVer){
  exit(0);
}

##For Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17728"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
