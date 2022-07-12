###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Vista Information Disclosure Vulnerability (931213)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801718");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-14 09:03:25 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-2229");
  script_bugtraq_id(24411);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Vista Information Disclosure Vulnerability (931213)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/25623");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Jun/1018225.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms07-032.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attacker to obtain sensitive information
  that may allow them to gain unauthorized access to the affected computer.");
  script_tag(name:"affected", value:"Microsoft Windows Vista.");
  script_tag(name:"insight", value:"The flaw is due to certain user information data being stored in the
  registry and the local file system with insecure permissions.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-032.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"931213") == 0){
  exit(0);
}

dllPath = registry_get_sz(item:"PathName",
                          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\system32\wmi.dll");

dllVer = GetVer(file:file, share:share);
if(dllVer)
{
  if(hotfix_check_sp(winVista:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6000.16470")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
         exit(0);
  }
}
