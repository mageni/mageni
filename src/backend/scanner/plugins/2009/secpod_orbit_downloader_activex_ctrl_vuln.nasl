###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_orbit_downloader_activex_ctrl_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Orbit Downloader File Deletion ActiveX Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900489");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-03-31 07:06:59 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-1064");
  script_bugtraq_id(34200);
  script_name("Orbit Downloader File Deletion ActiveX Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8257");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49353");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in a
  crafted webpage and trick the victim to visit the malicious link which lets
  the attacker execute the vulnerable code into the context of the affected remote system.");

  script_tag(name:"insight", value:"Bug in the 'download()' function method which lets the attacker to delete
  arbitrary files in the victim's computer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Orbit Downloader Version 3.0 or later.

  Workaround:
  Set the Killbit for the vulnerable CLSID {3F1D494B-0CEF-4468-96C9-386E2E4DEC90}");

  script_tag(name:"summary", value:"This host is installed with Orbit Downloader and is prone to
  File Deletion ActiveX Vulnerability.");

  script_tag(name:"affected", value:"Orbit Downloader 'Orbitmxt.dll' version 2.1.0.2 and prior.");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  script_xref(name:"URL", value:"http://www.orbitdownloader.com");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

orbitName = registry_get_sz(key:"SOFTWARE\Orbit", item:"path");
if(!orbitName){
  exit(0);
}

dllPath = orbitName + "\orbitmxt.dll";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

dllVer = GetVer(file:file, share:share);
if(dllVer != NULL)
{
  if(version_is_less_equal(version:dllVer, test_version:"2.1.0.2"))
  {
    # Workaround check
    if(is_killbit_set(clsid:"{3F1D494B-0CEF-4468-96C9-386E2E4DEC90}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
