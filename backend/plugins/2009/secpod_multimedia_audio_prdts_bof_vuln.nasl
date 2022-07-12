###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_multimedia_audio_prdts_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# MultiMedia Soft Audio Products Buffer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900458");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(33589);
  script_cve_id("CVE-2009-0476");
  script_name("MultiMedia Soft Audio Products Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33791");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7973");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"affected", value:"Following components with AdjMmsEng.dll file version 7.11.2.7 and prior.

  MultiMedia Soft Audio DJ Studio for .NET

  MultiMedia Soft Audio Sound Recorder for .NET

  MultiMedia Soft Audio Sound Editor for .NET");

  script_tag(name:"insight", value:"The vulnerability exists in AdjMmsEng.dll file of multiple MultiMedia Soft
  audio components for .NET. This issue arises due to failure in performing
  adequate boundary checks on user supplied input to the application buffer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest versions.");

  script_tag(name:"summary", value:"This host is running MultiMedia Soft Audio Products and is prone
  to Buffer Overflow Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application through crafted playlist files 'file.pls' with
  overly long data which may lead to crashing of the application.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\";
if(!registry_key_exists(key:key))exit(0);

foreach item(registry_enum_keys(key:key))
{
  if(item =~ "(MMS.AudioDjStudio|MMS.AudioSoundEditor|MMS.AudioSoundRecorder)")
  {
    djPath = registry_get_sz(key:key + item, item:"InstPath");
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:djPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:djPath +
                        "\Redist\AdjMmsEng.dll");
    version = GetVer(file:file, share:share);
    if(version != NULL)
    {
      if(version_is_less_equal(version:version, test_version:"7.11.2.7"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
