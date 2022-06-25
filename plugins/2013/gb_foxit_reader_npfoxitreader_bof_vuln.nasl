###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_npfoxitreader_bof_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Foxit Reader Plugin URL Processing Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803163");
  script_version("$Revision: 11865 $");
  script_bugtraq_id(57174);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-24 13:51:25 +0530 (Thu, 24 Jan 2013)");
  script_name("Foxit Reader PDF File Handling Memory Corruption Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51733");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027953");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23944");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/support/security_bulletins.php#FRD-18");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  on the target system.");
  script_tag(name:"affected", value:"Foxit Reader version 5.4.4.1128 and prior");
  script_tag(name:"insight", value:"The is flaw is due to a boundary error in the Foxit Reader plugin for
  browsers (npFoxitReaderPlugin.dll) when processing a URL and can be
  exploited to cause a stack-based buffer overflow via an overly long
  file name in the URL.");
  script_tag(name:"solution", value:"Upgrade to the Foxit Reader version 5.4.5 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is installed with Foxit Reader and is prone to buffer
  overflow vulnerability.");

  script_xref(name:"URL", value:"http://www.foxitsoftware.com/Secure_PDF_Reader");
  exit(0);
}

include("version_func.inc");

foxitVer = get_kb_item("foxit/reader/ver");
if(!foxitVer){
  exit(0);
}

if(version_is_less_equal(version:foxitVer, test_version:"5.4.4.1128")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
