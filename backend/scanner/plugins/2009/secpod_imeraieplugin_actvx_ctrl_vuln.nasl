#################################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_imeraieplugin_actvx_ctrl_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Imera TeamLinks ImeraIEPlugin.dll ActiveX Control DoS Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
#################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900520");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0813");
  script_bugtraq_id(33993);
  script_name("Imera TeamLinks ImeraIEPlugin.dll ActiveX Control DoS Vulnerability");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8144");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49028");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2009/Mar/0086.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Attacker may exploit this issue to download and execute arbitrary script code
  on the victim's system by passing malicious URLs and may crash the application.");
  script_tag(name:"affected", value:"Imera Systems ImeraIEPlugin.dll version 1.0.2.54 on Windows.");
  script_tag(name:"insight", value:"This issue is caused by errors in the ImeraIEPlugin.dll control while
  processing the URLs passed into DownloadProtocol, DownloadHost, DownloadPort
  and DownloadURI parameters.");
  script_tag(name:"summary", value:"This host is installed with Imera ImeraIEPlugin ActiveX and
  is prone to denial of service vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

imeraName = registry_get_sz(key:"SOFTWARE\ImeraIBCPilot", item:"Name");
if("Imera TeamLinks" >< imeraName)
{
  imeraPath = registry_get_sz(key:"SOFTWARE\ImeraIBCPilot", item:"Install_Dir");
  if(imeraPath == NULL){
    exit(0);
  }
}

imeraPath = imeraPath + "\ImeraIEPlugin\ImeraIEPlugin.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:imeraPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:imeraPath);
imeradllVer = GetVer(share:share, file:file);

if(imeradllVer != NULL)
{
  if(version_is_less_equal(version:imeradllVer, test_version:"1.0.2.54"))
  {
    if(is_killbit_set(clsid:"{75CC8584-86D4-4A50-B976-AA72618322C6}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
