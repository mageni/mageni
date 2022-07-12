###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_pdf_mem_crptn_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Foxit Reader PDF File Handling Memory Corruption Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802957");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-4337");
  script_bugtraq_id(55150);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-07 11:03:23 +0530 (Fri, 07 Sep 2012)");
  script_name("Foxit Reader PDF File Handling Memory Corruption Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50359");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027424");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  on the target system.");
  script_tag(name:"affected", value:"Foxit Reader version prior to 5.3 on Windows XP and Windows 7");
  script_tag(name:"insight", value:"An unspecified error when parsing PDF files and can be exploited to corrupt
  memory.");
  script_tag(name:"solution", value:"Upgrade to the Foxit Reader version 5.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is installed with Foxit Reader and is prone to memory
  corruption vulnerability.");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/Secure_PDF_Reader/");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win7:2, win7x64:2) <= 0){
  exit(0);
}

foxitVer = get_kb_item("foxit/reader/ver");
if(!foxitVer){
  exit(0);
}

if(version_is_less(version:foxitVer, test_version:"5.3.0.0423")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
