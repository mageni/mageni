###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerability in SMBv2 Could Allow Remote Code Execution (942624)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801711");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-5351");
  script_bugtraq_id(26777);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Vulnerability in SMBv2 Could Allow Remote Code Execution (942624)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/27997");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/38725");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Dec/1019072.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms07-063.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  in the context of logged-in users.");
  script_tag(name:"affected", value:"Microsoft Windows Vista.");
  script_tag(name:"insight", value:"The flaw is due to an improper implementation of SMBv2 signing and can
  be exploited to execute arbitrary code by spoofing the signature in a SMBv2
  packet to a trusted host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-063.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"942624") == 0){
  exit(0);
}

dllPath = registry_get_sz(item:"PathName",
                          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\system32\drivers\mrxsmb.sys");

dllVer = GetVer(file:file, share:share);
if(dllVer)
{
  if(hotfix_check_sp(winVista:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6000.20709")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
