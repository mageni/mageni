###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Lync Remote Code Execution Vulnerabilities (2707956)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902842");
  script_version("2019-05-03T12:31:27+0000");
  script_bugtraq_id(50462, 53335, 53831, 53833);
  script_cve_id("CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849", "CVE-2012-1858");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-06-13 11:11:11 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft Lync Remote Code Execution Vulnerabilities (2707956)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48429");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027150");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-039");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code
  with kernel-level privileges. Failed exploit attempts may result in a
  denial of service condition.");
  script_tag(name:"affected", value:"Microsoft Lync 2010,
  Microsoft Lync 2010 Attendee,
  Microsoft Lync 2010 Attendant,
  Microsoft Communicator 2007 R2.");
  script_tag(name:"insight", value:"- An error within the Win32k kernel-mode driver (win32k.sys) when parsing
    TrueType fonts.

  - An error in the t2embed.dll module when parsing TrueType fonts.

  - The client loads libraries in an insecure manner, which can be exploited
    to load arbitrary libraries by tricking a user into opening a '.ocsmeet'
    file located on a remote WebDAV or SMB share.

  - An unspecified error in the 'SafeHTML' API when sanitising HTML code can
    be exploited to execute arbitrary HTML and script code in the user's chat
    session.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-039.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(get_kb_item("MS/Lync/Ver"))
{
  path = get_kb_item("MS/Lync/path");
  if(path)
  {
    commVer = fetch_file_version(sysPath:path, file_name:"communicator.exe");
    if(commVer)
    {
      if(version_in_range(version:commVer, test_version:"3.5", test_version2:"3.5.6907.252")||
         version_in_range(version:commVer, test_version:"4.0", test_version2:"4.0.7577.4097"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## For Microsoft Lync 2010 Attendee (admin level install)
## For Microsoft Lync 2010 Attendee (user level install)
if(get_kb_item("MS/Lync/Attendee/Ver"))
{
  path = get_kb_item("MS/Lync/Attendee/path");
  if(path)
  {
    oglVer = fetch_file_version(sysPath:path, file_name:"Ogl.dll");
    if(oglVer)
    {
      if(version_in_range(version:oglVer, test_version:"4.0", test_version2:"4.0.7577.4097"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

if(get_kb_item("MS/Lync/Attendant/Ver"))
{
  path = get_kb_item("MS/Lync/Attendant/path");
  if(path)
  {
    attVer = fetch_file_version(sysPath:path, file_name:"AttendantConsole.exe");
    if(attVer)
    {
      if(version_in_range(version:attVer, test_version:"4.0", test_version2:"4.0.7577.4097"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
