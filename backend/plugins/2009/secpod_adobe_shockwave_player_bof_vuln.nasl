###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_player_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Adobe Shockwave Player ActiveX Control BOF Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated the Fix.
# - Nikita MR <rnikita@secpod.com> 2009-11-06
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
  script_oid("1.3.6.1.4.1.25623.1.0.900949");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3244");
  script_bugtraq_id(36434, 36905);
  script_name("Adobe Shockwave Player ActiveX Control BOF Vulnerability");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9682");
  script_xref(name:"URL", value:"http://get.adobe.com/shockwave/otherversions/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful attack could allow attackers to execute arbitrary code and to
  cause denial of service.");

  script_tag(name:"affected", value:"Adobe Shockwave Player 11.5.1.601 and prior on Windows.");

  script_tag(name:"insight", value:"An error occurs in the ActiveX Control (SwDir.dll) while processing malicious
  user supplied data containing a long PlayerVersion property value.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.2.602.");

  script_tag(name:"summary", value:"This host has Adobe Shockwave Player ActiveX Control installed
  and is prone to Buffer Overflow vulnerability.");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less_equal(version:shockVer, test_version:"11.5.1.601"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                           item:"Install Path");
  if(dllPath == NULL){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath +
                               "\Adobe\Director\SwDir.dll");

  dllOpn = open_file(share:share, file:file);
  if(isnull(dllOpn))
  {
    file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath +
                                              "\Macromed\Director\SwDir.dll");
    dllOpn = open_file(share:share, file:file);
  }

  if(dllOpn &&
     is_killbit_set(clsid:"{233C1507-6A77-46A4-9443-F871F945D258}") == 0){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
