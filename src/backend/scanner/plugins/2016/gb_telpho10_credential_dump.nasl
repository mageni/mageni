###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_telpho10_credential_dump.nasl 10833 2018-08-08 10:35:26Z cfischer $
#
# Telpho10 Credentials Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:telpho:telpho10";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140076");
  script_version("$Revision: 10833 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 12:35:26 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-11-21 13:35:52 +0100 (Mon, 21 Nov 2016)");
  script_name("Telpho10 Credentials Disclosure Vulnerability");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_telpho10_web_interface_detect.nasl");
  script_mandatory_keys("telpho10/webinterface/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"It is possible to create and read a configuration backup of Telpho10.
  This backup contains the credentials for admin login.");

  script_tag(name:"vuldetect", value:"Try to generate and read a configuration backup.");

  script_tag(name:"affected", value:"Telpho10 <= 2.6.31");

  script_tag(name:"solution", value:"Upgrade to version 2.6.32 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
url = '/telpho/system/backup.php';
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req );

if( buf !~ "^HTTP/1\.[01] 200" ) exit( 0 );

url1 = '/telpho/temp/telpho10.epb';
req = http_get( item:url1, port:port );
buf = http_send_recv( port:port, data:req );

if( buf =~ "HTTP/1\.. 200" && "control.tar" >< buf && "ustar" >< buf ){
  report = 'By requesting ' + report_vuln_url(  port:port, url:url, url_only:TRUE ) + ' it was possible to generate a backup of the device.\nThis backup could be retrieved by requesting ' +
           report_vuln_url(  port:port, url:url1, url_only:TRUE ) + '.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
