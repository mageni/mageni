###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_file_server_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# HTTP File Server Multiple Vulnerabilities
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

CPE = "cpe:/a:httpfilesever:hfs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803171");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-19 15:17:57 +0530 (Tue, 19 Feb 2013)");
  script_name("HTTP File Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://1337day.com/exploit/20345");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2013/02/http-file-server-v2x-xss-and-file.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_http_file_server_detect.nasl");
  script_mandatory_keys("hfs/Installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to insert arbitrary
  HTML and script code and execute arbitrary PHP code.");
  script_tag(name:"affected", value:"HttpFileServer version 2.2f and prior");
  script_tag(name:"insight", value:"- An input passed to 'search' parameter is not properly sanitized
  before being returned to the user.

  - An error due to the '~upload ' script allowing the upload of files with
  arbitrary extensions to a folder inside the webroot can be exploited to
  execute arbitrary PHP code by uploading a malicious PHP script.");
  script_tag(name:"solution", value:"Update to version 2.3 or later.");
  script_tag(name:"summary", value:"This host is running HTTP File Server and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.rejetto.com/hfs");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! hfsPort = get_app_port( cpe:CPE ) ) exit(0);
if( ! hfsVer = get_app_version( cpe:CPE, port:hfsPort ) ) exit(0);

if( version_is_less( version:hfsVer, test_version:"2.3" ) ) {
  report = report_fixed_ver( installed_version: hfsVer, fixed_version: "2.3" );
  security_message( port:hfsPort, data:report );
  exit( 0 );
}

exit( 99 );