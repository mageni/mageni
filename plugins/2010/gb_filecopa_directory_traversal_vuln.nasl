###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filecopa_directory_traversal_vuln.nasl 13605 2019-02-12 13:43:31Z cfischer $
#
# FileCopa FTP Server Directory Traversal Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.800179");
  script_version("$Revision: 13605 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 14:43:31 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2112");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_name("FileCopa FTP Server Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39843");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("FTP");
  script_dependencies("gb_filecopa_ftp_server_detect.nasl");
  script_mandatory_keys("FileCOPA-FTP-Server/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to read or overwrite arbitrary
  files via unknown vectors.");

  script_tag(name:"affected", value:"FileCopa FTP Server version before 5.03 on Windows.");

  script_tag(name:"insight", value:"An input validation error exists within the FTP service, which can be
  exploited to download or upload arbitrary files outside the FTP root
  via directory traversal attack.");

  script_tag(name:"solution", value:"Upgrade to FileCopa FTP Server version 5.03 or later.");

  script_tag(name:"summary", value:"This host is running FileCopa FTP Server and is prone to
  directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

filecopaVer = get_kb_item("FileCOPA-FTP-Server/Ver");
if(!filecopaVer){
  exit(0);
}

if(version_is_less(version:filecopaVer, test_version:"5.03")){
  security_message(port:0);
}
