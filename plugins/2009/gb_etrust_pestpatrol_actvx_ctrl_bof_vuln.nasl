###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_etrust_pestpatrol_actvx_ctrl_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# CA eTrust PestPatrol Anti-Spyware 'ppctl.dll' ActiveX Control BOF Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801098");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4225");
  script_bugtraq_id(37133);
  script_name("CA eTrust PestPatrol Anti-Spyware 'ppctl.dll' ActiveX Control BOF Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54458");
  script_xref(name:"URL", value:"http://www.fortiguard.com/encyclopedia/vulnerability/ca.etrust.pestpatrol.ppctl.dll.activex.access.html");
  script_xref(name:"URL", value:"http://www.metasploit.com/redmine/projects/framework/repository/revisions/7167/entry/modules/exploits/windows/fileformat/etrust_pestscan.rb");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code, and cause the
  victim's browser to crash.");
  script_tag(name:"affected", value:"CA eTrust PestPatrol Anti-Spyware");
  script_tag(name:"insight", value:"A Stack-based buffer overflow error in ActiveX control in 'ppctl.dll', which
  can be caused by persuading a victim to visit a specially-crafted Web page
  that passes an overly long string argument to the 'Initialize()' method.");
  script_tag(name:"summary", value:"This host is installed with CA eTrust PestPatrol Anti-Spyware and
  is prone to Buffer Overflow vulnerability.");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

ppPath = registry_get_sz(key:"SOFTWARE\ComputerAssociates\eTrustPestPatrol",
                         item:"InstallPath");
if(ppPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ppPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ppPath +
                      "\ppctl.dll");
  ppVer = GetVer(file:file, share:share);

  if(ppVer)
  {
    if(version_is_equal(version:ppVer, test_version:"5.6.7.9"))
    {
      if(is_killbit_set(clsid:"{5e644c49-f8b0-4e9a-a2ed-5f176bb18ce6}") == 0){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
