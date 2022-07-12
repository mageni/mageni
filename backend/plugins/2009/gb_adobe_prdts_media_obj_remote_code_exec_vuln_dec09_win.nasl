###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_media_obj_remote_code_exec_vuln_dec09_win.nasl 12632 2018-12-03 17:55:22Z cfischer $
#
# Adobe Reader/Acrobat Multimedia Doc.media.newPlayer Code Execution Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.901096");
  script_version("$Revision: 12632 $");
  script_cve_id("CVE-2009-4324");
  script_bugtraq_id(37331);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 18:55:22 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)");
  script_name("Adobe Reader/Acrobat Multimedia Doc.media.newPlayer Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to
  Doc.media.newPlayer Remote Code Execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There exists a flaw in the JavaScript module doc.media object while sending a
  null argument to the newPlayer() method as the exploitation method makes use of a vpointer that has not been initialized.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code and
  compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Acrobat version 9.2.0 and prior.

  Adobe Acrobat version 9.2.0 and prior.");

  script_tag(name:"solution", value:"Upgrade Adobe Reader version 9.3.2 or later.

  Workaround: Disable JavaScript execution from the Adobe Acrobat/Reader product
  configuration menu settings.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.f-secure.com/weblog/archives/00001836.html");
  script_xref(name:"URL", value:"http://extraexploit.blogspot.com/search/label/CVE-2009-4324");
  script_xref(name:"URL", value:"http://www.shadowserver.org/wiki/pmwiki.php/Calendar/20091214");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2009/12/new_adobe_reader_and_acrobat_v.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/adobe_media_newplayer.rb");
  script_xref(name:"URL", value:"http://vrt-sourcefire.blogspot.com/2009/12/adobe-reader-medianewplayer-analysis.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less_equal(version:readerVer, test_version:"9.2.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_is_less_equal(version:acrobatVer, test_version:"9.2.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
