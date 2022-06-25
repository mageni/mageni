###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synactis_allinthebox_activex_code_exec_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Synactis All-In-The-Box ActiveX Remote Code Execution Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800245");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-02-13 14:28:43 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0465");
  script_bugtraq_id(33535);
  script_name("Synactis All-In-The-Box ActiveX Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33728");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7928");
  script_xref(name:"URL", value:"http://www.dsecrg.com/pages/vul/show.php?id=62");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  script_xref(name:"URL", value:"http://synactis.com/pdf-in-the-box-downloads.asp");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker overwrite arbitrary files on
  the system via a filename terminated by a NULL byte.");

  script_tag(name:"insight", value:"This flaw is due to an ActiveX control All_In_The_Box.ocx providing insecure
  SaveDoc method.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Synactis, All-In-The-Box ActiveX version 4.02 or later.

  Workaround:
  Set the Killbit for the vulnerable CLSID {B5576893-F948-4E0F-9BE1-A37CB56D66FF}");

  script_tag(name:"summary", value:"This host is installed with All-In-The-Box ActiveX and is prone to
  Remote Code Execution Vulnerability.");

  script_tag(name:"affected", value:"Synactis, All-In-The-Box ActiveX version 3.1.2.0 and prior.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

ocxPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Synactis_All_In-The-Box_ActiveX",
                          item:"Unregister");
if(!ocxPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ocxPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ocxPath);

ocxVer = GetVer(file:file, share:share);
if(!ocxVer){
  exit(0);
}

if(version_is_less_equal(version:ocxVer, test_version:"3.1.2.0"))
{
  if(is_killbit_set(clsid:"{B5576893-F948-4E0F-9BE1-A37CB56D66FF}") == 0){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
