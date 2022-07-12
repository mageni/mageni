###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fujitsu_syswizard_lite_mult_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# FUJITSU SystemWizard Lite Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900456");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-01-30 14:33:42 +0100 (Fri, 30 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0264", "CVE-2009-0270", "CVE-2009-0271");
  script_bugtraq_id(33344);
  script_name("FUJITSU SystemWizard Lite Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33594");
  script_xref(name:"URL", value:"http://securityvulns.com/Vdocument198.html");
  script_xref(name:"URL", value:"http://www.wintercore.com/advisories/advisory_W010109.html");
  script_xref(name:"URL", value:"http://primeserver.fujitsu.com/primequest/products/os/windows2008.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes via
  a large PXE protocol request in a UDP packet and also directory traversal
  attack sequences in unspecified vectors.");

  script_tag(name:"affected", value:"FUJITSU SystemWizard Lite version 2.0A and prior on Windows.");

  script_tag(name:"insight", value:"Improper boundary check of input data in DefaultSkin.ini in TFTP service,
  Registry Setting Tool and PXEService.exe files.");

  script_tag(name:"solution", value:"Apply the security patches from the linked references.");

  script_tag(name:"summary", value:"This host is installed with FUJITSU SystemWizard Lite and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\FUJITSU")){
  exit(0);
}

key = "SOFTWARE\FUJITSU\SystemcastWizard";
fuziVer = registry_get_sz(key:"SOFTWARE\FUJITSU\SystemcastWizard",
                          item:"ProductVersion");
if(!fuziVer){
  exit(0);
}

wizardVer =  eregmatch(pattern:"V([0-9.]+A?)", string:fuziVer);
if(wizardVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:wizardVer[1], test_version:"1.6A"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

if(version_is_less_equal(version:wizardVer[1], test_version:"2.0A"))
{
  key = "SOFTWARE\FUJITSU\SystemcastWizard";
  path = registry_get_sz(key:key, item:"InstallPath");
  if(!path){
    exit(0);
  }

  dllPath = path + "bin\ChkPXESv.dll";
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:dllPath);

  dllVer = GetVer(share:share, file:file);
  if(!dllVer){
    exit(0);
  }

  if(version_is_less(version:dllVer, test_version:"4.0.11.530")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
