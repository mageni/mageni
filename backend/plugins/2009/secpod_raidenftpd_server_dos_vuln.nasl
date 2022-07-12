###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_raidenftpd_server_dos_vuln.nasl 13605 2019-02-12 13:43:31Z cfischer $
#
# RaidenFTPD Server CWD and MLST Command Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900511");
  script_version("$Revision: 13605 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 14:43:31 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6186");
  script_bugtraq_id(31741);
  script_name("RaidenFTPD Server CWD and MLST Command Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32216");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6742");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_raidenftpd_server_detect.nasl");
  script_mandatory_keys("RaidenFTPD/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the user crash the application to cause
  denial of service.");

  script_tag(name:"affected", value:"RaidenFTPD Server version 2.4.3620 and prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when handling overly long requested
  directory names. As a result buffer overflow can be caused using specially crafted CWD and MLST commands.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"This host is running RaidenFTPD Server and is prone to Denial of
  Service Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

rftpdVer = get_kb_item("RaidenFTPD/Ver");
if(!rftpdVer){
  exit(0);
}

if(version_is_less_equal(version:rftpdVer, test_version:"2.4.3620")){
  security_message(port:0);
}
