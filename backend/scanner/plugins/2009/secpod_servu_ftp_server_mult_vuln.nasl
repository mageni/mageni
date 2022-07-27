###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_servu_ftp_server_mult_vuln.nasl 12605 2018-11-30 15:22:13Z cfischer $
#
# Rhinosoft Serv-U FTP Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900483");
  script_version("$Revision: 12605 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 16:22:13 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:23:52 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_cve_id("CVE-2009-0967", "CVE-2009-1031");
  script_bugtraq_id(34127, 34125);
  script_name("Rhinosoft Serv-U FTP Multiple Vulnerabilities");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_servu_ftp_server_detect.nasl");
  script_mandatory_keys("Serv-U/FTPServ/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker conduct directory traversal
  attack or can cause denial of service.");

  script_tag(name:"affected", value:"Rhinosoft Serv-U FTP Server version 7.4.0.1 or prior.");

  script_tag(name:"insight", value:"- Error when processing 'MKD' commands which can be exploited to create
  directories residing outside a given user's home directory via directory traversal attacks.

  - Error when handing certain FTP commands, by sending a large number of 'SMNT' commands without an argument
  causes the application to stop responding.");

  script_tag(name:"solution", value:"Upgrade to Rhinosoft Serv-U FTP Server version 10 or later.");

  script_tag(name:"summary", value:"This host is running Serv-U FTP Server and is prone to multiple
  vulnerabilities.");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8211");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8212");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49260");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0738");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

servuVer = get_kb_item("Serv-U/FTPServ/Ver");
if(!servuVer){
  exit(0);
}

if(version_is_less_equal(version:servuVer, test_version:"7.4.0.1")){
  security_message(port:0);
}