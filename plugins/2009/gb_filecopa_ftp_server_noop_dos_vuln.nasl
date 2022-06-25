###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filecopa_ftp_server_noop_dos_vuln.nasl 13605 2019-02-12 13:43:31Z cfischer $
#
# FileCopa FTP Server 'NOOP' Command DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801125");
  script_version("$Revision: 13605 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 14:43:31 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3662");
  script_bugtraq_id(36397);
  script_name("FileCopa FTP Server 'NOOP' Command DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36773");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/36397.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_filecopa_ftp_server_detect.nasl");
  script_mandatory_keys("FileCOPA-FTP-Server/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a Denial of Service.");

  script_tag(name:"affected", value:"FileCopa FTP Server version 5.01 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error in the handling of 'NOOP' FTP commands.
  This can be exploited to hang an affected server via an overly large number
  of specially crafted NOOP commands.");

  script_tag(name:"solution", value:"Upgrade to FileCopa FTP Server version 5.02.");

  script_tag(name:"summary", value:"This host is running FileCopa FTP Server and is prone to Denial of
  Service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

filecopaVer = get_kb_item("FileCOPA-FTP-Server/Ver");
if(!filecopaVer){
  exit(0);
}

if(version_is_less(version:filecopaVer, test_version:"5.02")){
  security_message(port:0);
}