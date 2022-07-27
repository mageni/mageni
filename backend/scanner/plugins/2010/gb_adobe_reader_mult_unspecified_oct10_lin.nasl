###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_oct10_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Reader Multiple Unspecified Vulnerabilities -Oct10 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801525");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_cve_id("CVE-2010-2887");
  script_bugtraq_id(43740);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -Oct10 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41435/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2573");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-21.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to gain privileges via unknown
  vectors.");
  script_tag(name:"affected", value:"Adobe Reader version 8.x before 8.2.5 and 9.x before 9.4 on linux");
  script_tag(name:"insight", value:"An unspecified flaw is present in the application which can be exploited
  through an unknown attack vectors.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.4 or 8.2.5");
  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to multiple
  unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(!readerVer){
  exit(0);
}

if(version_is_less(version:readerVer, test_version:"8.2.5") ||
   version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
