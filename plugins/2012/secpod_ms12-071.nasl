###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Use-After-Free Vulnerabilities (2761451)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.902932");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2012-1538", "CVE-2012-1539", "CVE-2012-4775");
  script_bugtraq_id(56420, 56421, 56422);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2012-11-14 09:38:03 +0530 (Wed, 14 Nov 2012)");
  script_name("Microsoft Internet Explorer Multiple Use-After-Free Vulnerabilities (2761451)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51202/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2761451");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2761451");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2761451");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2761451");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-071");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x");

  script_tag(name:"insight", value:"Multiple use-after-free errors within the 'CFormElement', 'CTreePos' and
  'CTreeNode' class and can be exploited to dereference already freed memory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-071.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer || ieVer !~ "^9\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16454")||
   version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20561")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
