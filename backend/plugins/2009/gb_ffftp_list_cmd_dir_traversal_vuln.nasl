###############################################################################
# OpenVAS Vulnerability Test
#
# FFFTP LIST Command Directory Traversal Vulnerability.
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800533");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_cve_id("CVE-2008-6424");
  script_bugtraq_id(29459);
  script_name("FFFTP LIST Command Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30428/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/1708/references");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_ffftp_detect.nasl");
  script_mandatory_keys("FFFTP/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to create or overwrite
  arbitrary files on a vulnerable system by tricking a user into downloading
  a directory containing files.");
  script_tag(name:"affected", value:"FFFTP version 1.96b and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to input validation error when processing FTP
  responses to a LIST command with a filename and is followed by ../ (dot dot
  forward-slash).");
  script_tag(name:"solution", value:"Upgrade to version 1.96d or later.");
  script_tag(name:"summary", value:"This host is installed with FFFTP Client and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffftpVer = get_kb_item("FFFTP/Ver");
if(!ffftpVer)
  exit(0);

if(version_is_less_equal(version:ffftpVer, test_version:"1.96.2.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
