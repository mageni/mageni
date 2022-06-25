##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typsoft_ftp_server_dos_vuln.nasl 13605 2019-02-12 13:43:31Z cfischer $
#
# TYPSoft FTP Server 'APPE' and 'DELE' Commands DOS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801058");
  script_version("$Revision: 13605 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 14:43:31 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_bugtraq_id(37114);
  script_cve_id("CVE-2009-4105");
  script_name("TYPSoft FTP Server 'APPE' and 'DELE' Commands DOS Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54407");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Nov/1023234.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_typsoft_ftp_detect.nasl");
  script_mandatory_keys("TYPSoft/FTP/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the user crash the application to
  cause denial of service.");

  script_tag(name:"affected", value:"TYPSoft FTP Server version 1.10 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling the 'APPE' and 'DELE'
  commands. These can be exploited through sending multiple login request in same socket.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to version 1.11 or later.");

  script_tag(name:"summary", value:"This host is running TYPSoft FTP Server and is prone to Denial of
  Service Vulnerability.");

  script_xref(name:"URL", value:"http://www.softpedia.com/get/Internet/Servers/FTP-Servers/TYPSoft-FTP-Server.shtml");

  exit(0);
}

include("version_func.inc");


tsftpVer = get_kb_item("TYPSoft/FTP/Ver");
if(tsftpVer != NULL)
{
  if(version_is_less_equal(version:tsftpVer, test_version:"1.10")){
    security_message(port:0);
  }
}