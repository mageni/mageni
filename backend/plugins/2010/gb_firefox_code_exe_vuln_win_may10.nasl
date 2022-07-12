###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_code_exe_vuln_win_may10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Firefox Code Execution Vulnerability (Windows) - May10
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801326");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-1585");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Code Execution Vulnerability (Windows) - May10");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/510883/100/0/threaded");
  script_xref(name:"URL", value:"http://wizzrss.blat.co.za/2009/11/17/so-much-for-nsiscriptableunescapehtmlparsefragment/");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/whitepapers/Cross_Context_Scripting_with_Firefox.pdf");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary JavaScript
  with chrome privileges via a javascript: URI in input to an extension.");
  script_tag(name:"affected", value:"Firefox version prior to 3.6 on Windows");
  script_tag(name:"insight", value:"The flaw is due to error in 'nsIScriptableUnescapeHTML.parseFragment'
  method which does not properly sanitize 'HREF' attribute of an 'A' element
  or the 'ACTION' attribute of a 'FORM' element.");
  script_tag(name:"solution", value:"Upgrade to  Firefox version prior to 3.6.3 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to code execution vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less_equal(version:ffVer, test_version:"3.6")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
