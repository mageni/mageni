###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Expression Design Remote Code Execution Vulnerability (2651018)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903000");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0016");
  script_bugtraq_id(52375);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-03-14 10:53:40 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Expression Design Remote Code Execution Vulnerability (2651018)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48353/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026791");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-022");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_expression_design_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Expression/Design/Ver", "MS/Expression/Install/Path");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on the target system.");
  script_tag(name:"affected", value:"Microsoft Expression Design
  Microsoft Expression Design 2
  Microsoft Expression Design 3
  Microsoft Expression Design 4
  Microsoft Expression Design Service Pack 1");
  script_tag(name:"insight", value:"The flaw is due to the way that Microsoft Expression Design handles
  the loading of DLL files. An attacker can exploit this vulnerability to
  install programs, view, change, or delete data, or create new accounts with
  full user rights.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-022.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


function version_check(ver)
{
  if(version_is_equal(version:ver, test_version:"4.0.2712.0") ||
     version_is_equal(version:ver, test_version:"4.0.2920.0")||
     version_is_equal(version:ver, test_version:"5.0.1379.0")||
     version_is_equal(version:ver, test_version:"6.0.1739.0")||
     version_is_equal(version:ver, test_version:"7.0.20516.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

desinVer = get_kb_item("MS/Expression/Design/Ver");

path = get_kb_item("MS/Expression/Install/Path");
if(!path){
  exit(0);
}

if(desinVer && (desinVer =~ "^[4|5]\.*"))
{
  ## For diff versions of MS Expression Design and MS Expression Design 2
  foreach ver (make_list("1.0", "2"))
  {
    dllPath = path + "Design" + " " + ver;

    dllVer = fetch_file_version(sysPath:dllPath, file_name:"GraphicsCore.dll");
    if(!dllVer){
      continue;
    }
    version_check(ver:dllVer);
  }
}

dllVer = fetch_file_version(sysPath:path, file_name:"GraphicsCore.dll");
if(dllVer){
  version_check(ver:dllVer);
}
