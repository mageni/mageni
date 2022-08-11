###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_code_exec_vuln_win.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Apple QuickTime Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801501");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_cve_id("CVE-2010-1818");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple QuickTime Remote Code Execution Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
code.");
  script_tag(name:"affected", value:"Apple QuickTime version 6.5.2 and prior
Apple QuickTime version 7.6.7 and prior on windows.");
  script_tag(name:"insight", value:"The flaw is due to error in 'IPersistPropertyBag2::Read()'
function in 'QTPlugin.ocx'. It allows remote attackers to execute arbitrary
code via the '_Marshaled_pUnk attribute', which triggers unmarshaling of an
untrusted pointer.");
  script_tag(name:"solution", value:"Upgrade to version 7.6.8 or later.");
  script_tag(name:"summary", value:"The host is installed with Apple QuickTime and is prone to
remote code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://reversemode.com/index.php?option=com_content&task=view&id=69&Itemid=1");
  script_xref(name:"URL", value:"http://threatpost.com/en_us/blogs/new-remote-flaw-apple-quicktime-bypasses-aslr-and-dep-083010");
  script_xref(name:"URL", value:"https://www.metasploit.com/redmine/projects/framework/repository/entry/modules/exploits/windows/browser/apple_quicktime_marshaled_punk.rb");
  script_xref(name:"URL", value:"http://www.apple.com/quicktime/download");
  exit(0);
}


include("version_func.inc");

qtVer = get_kb_item("QuickTime/Win/Ver");
if(!qtVer){
  exit(0);
}

if(qtVer =~ "^6\.5.*")
{
  # QuickTime version < 6.5.2
  if(version_is_less_equal(version:qtVer, test_version:"6.5.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

if(qtVer =~ "^7\.6.*")
{
  # QuickTime version < 7.6.7
  if(version_is_less_equal(version:qtVer, test_version:"7.6.7")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
