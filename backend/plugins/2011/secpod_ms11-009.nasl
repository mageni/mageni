###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft JScript and VBScript Scripting Engines Information Disclosure Vulnerability (2475792)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902336");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2011-0031");
  script_bugtraq_id(46139);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft JScript and VBScript Scripting Engines Information Disclosure Vulnerability (2475792)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/43249/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0322");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-009");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain access to
  sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");

  script_tag(name:"insight", value:"The flaw is caused by a memory corruption error in the JScript and VBScript
  scripting engines when processing scripts in Web pages.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-009.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(ieVer && ieVer =~ "^(9|1[01])\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(! sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Vbscript.dll");
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"5.8.7600.16732")||
   version_in_range(version:dllVer, test_version:"5.8.7600.20000", test_version2:"5.8.7600.20872")||
   version_in_range(version:dllVer, test_version:"5.8.7601.17000", test_version2:"5.8.7601.17534")||
   version_in_range(version:dllVer, test_version:"5.8.7601.21000", test_version2:"5.8.7601.21633")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
