###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_simple_ads_manager_plugin_mult_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Wordpress Simple Ads Manager Plugin Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805520");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2015-2824", "CVE-2015-2826");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-04-14 11:59:52 +0530 (Tue, 14 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Wordpress Simple Ads Manager Plugin Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Wordpress
  Simple Ads Manager Plugin and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST
  request and check whether it is is able to read sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The sam-ajax-admin.php script not properly sanitizing user-supplied input to
    the 'cstr', 'searchTer', 'subscriber', 'contributor', 'author', 'editor',
    'admin', and 'sadmin' POST parameters.

  - The error in handling a specially crafted POST request sent for the
    /sam-ajax-admin.php script with the 'action' parameter set to values such
    as 'load_users', 'load_authors', 'load_cats', 'load_tags', 'load_posts',
    'posts_debug', or 'load_stats'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data and gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"Wordpress Simple Ads Manager versions 2.5.94
  and 2.6.96");

  script_tag(name:"solution", value:"Upgrade to 2.7.97 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36613");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36615");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://profiles.wordpress.org/minimus");
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

url = dir + "/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php";

postData = "action=load_users";

useragent = http_get_user_agent();
host = http_host_name(port:http_port);

wpReq = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n",
               "\r\n", postData, "\r\n\r\n");
wpRes = http_keepalive_send_recv(port:http_port, data:wpReq);

if(wpRes && "id" >< wpRes && "title" >< wpRes && "slug" >< wpRes &&
            "role" >< wpRes && "recid" >< wpRes)
{
  security_message(http_port);
  exit(0);
}
