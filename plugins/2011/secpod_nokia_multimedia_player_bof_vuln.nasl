###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nokia_multimedia_player_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Nokia Multimedia Player Playlist Processing Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902331");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0498");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Nokia Multimedia Player Playlist Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42852");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0083");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is caused by a buffer overflow error when processing
playlists containing overly long data.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Nokia Multimedia Player and is prone
to buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an
affected application or compromise a vulnerable system by tricking a user into
opening a malicious playlist file.");
  script_tag(name:"affected", value:"Nokia Multimedia Player Version 1.00.55.5010 and prior");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Nokia\Nokia Multimedia Player")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  nmpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Nokia Multimedia Player" >< nmpName)
  {
    nmpPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(!isnull(nmpPath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:nmpPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:nmpPath +
                                                            "\NokiaMMSViewer.exe");
      nmpVer = GetVer(file:file, share:share);
      if(nmpVer != NULL)
      {
        if(version_is_less_equal(version:nmpVer, test_version:"1.0.0.55"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
