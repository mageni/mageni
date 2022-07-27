###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_afm_ftp_client_dir_traversal_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# AutoFTP Manager FTP Client Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801398");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)");
  script_cve_id("CVE-2010-3104");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("AutoFTP Manager FTP Client Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/396970.php");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/directory_traversal_in_autoftp_manager.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"insight", value:"The flaw exists due to error in handling of certain crafted file names.
  It does not properly sanitise filenames containing directory traversal
  sequences that are received from an FTP server.");

  script_tag(name:"solution", value:"Upgrade AutoFTP Manager FTP Client to recent versions.");

  script_tag(name:"summary", value:"This host is installed with AutoFTP Manager FTP Client and is prone
  to directory traversal vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to write files into a user's
  Startup folder to execute malicious code when the user logs on.");

  script_tag(name:"affected", value:"AutoFTP Manager FTP Client 4.31(4.3.1.0) and prior.");

  script_xref(name:"URL", value:"http://www.deskshare.com/download.aspx");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  afmName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Auto FTP Manager" >< afmName)
  {
    afmpath = registry_get_sz(key: key + item , item:"DisplayIcon");
    if(!isnull(afmpath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:afmpath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:afmpath);

      afmVer = GetVer(file:file, share:share);
      if(afmVer != NULL)
      {
        if(version_is_less_equal(version:afmVer, test_version:"4.3.1.0"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" ) ;
          exit(0);
        }
      }
    }
  }
}
