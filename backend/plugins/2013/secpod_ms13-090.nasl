###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows ActiveX Control RCE Vulnerability (2900986)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901225");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-3918");
  script_bugtraq_id(63631);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-11-13 12:27:27 +0530 (Wed, 13 Nov 2013)");
  script_name("Microsoft Windows ActiveX Control RCE Vulnerability (2900986)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-090.");

  script_tag(name:"vuldetect", value:"Get the ActiveX control (CLSID) information from registry and check
  appropriate patch is applied or not.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Flaw in the InformationCardSigninHelper Class ActiveX control (icardie.dll)
  and can be exploited to corrupt the system state.");

  script_tag(name:"affected", value:"Microsoft Windows 8

  Microsoft Windows Server 2012

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows XP x32 Edition Service Pack 3 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code when viewing a
  specially crafted web page using Internet Explorer.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55611");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-090");
  script_xref(name:"URL", value:"http://www.zdnet.com/microsoft-to-patch-zero-day-bug-tuesday-7000023066/");
  script_xref(name:"URL", value:"http://www.fireeye.com/blog/uncategorized/2013/11/new-ie-zero-day-found-in-watering-hole-attack.html");
  script_xref(name:"URL", value:"http://blogs.technet.com/b/msrc/archive/2013/11/11/activex-control-issue-being-addressed-in-update-tuesday.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
   win7:2, win7x64:2, win2008:3, win2008r2:2, win2012:1, win8:1,
   win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}


## CLSID List
clsids = make_list(
  "{19916e01-b44e-4e31-94a4-4696df46157b}",
  "{c2c4f00a-720e-4389-aeb9-e9c4b0d93c6f}",
  "{53001f3a-f5e1-4b90-9c9f-00e09b53c5f1}"
);

## Updated secpod_activex.inc to check for 67109888
## i.e 0x400 == 1024 and 0x4000400 == 67109888
## in the workaround also they have to set it as dword:04000400 == 67109888
## After applying the patch also killbit regisrty value is 0x4000400 == 67109888

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
