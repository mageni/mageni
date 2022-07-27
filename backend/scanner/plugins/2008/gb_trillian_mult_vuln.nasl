###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trillian_mult_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Trillian Messenger Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800205");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-12-17 15:03:38 +0100 (Wed, 17 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5401", "CVE-2008-5402", "CVE-2008-5403");
  script_bugtraq_id(32645);
  script_name("Trillian Messenger Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-077/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-078/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-079/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes
  in the context of the application and can compromise a vulnerable system.");

  script_tag(name:"affected", value:"Cerulean Studios, Trillian Messenger version prior to 3.1.12.0 on Windows.");

  script_tag(name:"insight", value:"This flaw is due to,

  - Boundary check error while generating XML Tags for images which can
  be exploited to cause stack overflow.

  - An error while processing XML codes which can be exploited to corrupt
  an internal data structure and can clear a heap chunk multiple times.

  - An boundary error while processing specially crafted XML tags which
  can cause a heap overflow.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the version latest 3.1.12.0.");

  script_tag(name:"summary", value:"This host is installed with Trillian Messenger and is prone to
  multiple remote memory corruption vulnerabilities.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

regKey = registry_key_exists(key:"SOFTWARE\Clients\IM\Trillian\InstallInfo");
if(!regKey){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Trillian";
exePath = registry_get_sz(key:key, item:"DisplayIcon");
if(exePath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);
  triVer = GetVer(file: file, share:share);

  if(triVer != NULL)
  {
    if(version_is_less(version:triVer, test_version:"3.1.12.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
