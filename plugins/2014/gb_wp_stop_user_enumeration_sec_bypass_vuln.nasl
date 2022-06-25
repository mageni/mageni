###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_stop_user_enumeration_sec_bypass_vuln.nasl 34987 2014-02-05 13:09:46Z Jan$
#
# WordPress Stop User Enumeration Security Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804084");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-05 13:09:46 +0530 (Wed, 05 Feb 2014)");
  script_name("WordPress Stop User Enumeration Security Bypass Vulnerability");


  script_tag(name:"summary", value:"This host is installed with WordPress Stop User Enumeration Plugin and is
prone to security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to
bypass security restriction or not.");
  script_tag(name:"insight", value:"Username enumeration protection for 'author' parameter via POST request
is not proper.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to enumerate users and get some
sensitive information, leads to further attacks.");
  script_tag(name:"affected", value:"WordPress Stop User Enumeration Plugin version 1.2.4, Other versions may also
be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/3");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/56643");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/current/0003.html");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-stop-user-enumeration-124-bypass");
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

url = dir + '/wp-content/plugins/stop-user-enumeration/stop-user-enumeration.php';
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<b>Fatal error</b>:  Call to undefined function "+
           "is_admin().*stop-user-enumeration.php</b>"))
{
  url = dir + '/index.php?author=1';

  if(http_vuln_check(port:http_port, url:url, check_header:'FALSE',
     pattern:"HTTP/1.. 500 Internal Server Error", extra_check:'>forbidden<'))
  {
    sndReq = string("POST ", dir,"/index.php HTTP/1.1\r\n",
                    "Host: ", get_host_name(), "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: 8\r\n",
                    "\r\nauthor=1\r\n");

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes =~ "HTTP/1.. 200 OK" && '>forbidden<' >!< rcvRes &&
       rcvRes !~ "HTTP/1.. 500 Internal Server Error")
    {
      security_message(http_port);
      exit(0);
    }
  }
}
