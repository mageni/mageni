###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_code_exec_vuln_win_may10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Opera Browser 'document.write()' Code execution Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801331");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1728");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser 'document.write()' Code execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39590");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58231");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/953/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0999");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1053/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to corrupt memory and execute
  arbitrary code by tricking a user into visiting a specially crafted web page.");
  script_tag(name:"affected", value:"Opera version prior to 10.53 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an error when continuously modifying document content
  on a web page using 'document.write()' function.");
  script_tag(name:"solution", value:"Upgrade to the opera version 10.53 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is installed with Opera web browser and is prone to
  arbitrary code execution vulnerability.");
  script_xref(name:"URL", value:"http://www.opera.com/download");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"10.53")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
