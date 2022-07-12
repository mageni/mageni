###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_flexolio_mult_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# WordPress Flexolio Multiple Vulnerabilities May14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804578");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-05-09 16:46:52 +0530 (Fri, 09 May 2014)");
  script_name("WordPress Flexolio Multiple Vulnerabilities May14");


  script_tag(name:"summary", value:"This host is installed with Wordpress Flexolio theme and is prone to
multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'xml', 'src' GET parameter to 'thumb.php' and 'cu3er.swf'
scripts are not properly sanitized before being returned to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code, disclose potentially sensitive information, and cause
denial of service.");
  script_tag(name:"affected", value:"WordPress Flexolio");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126475");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/May/15");
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

url = dir + '/wp-content/themes/flexolio/inc/thumb.php?src=1'
          + '%3Cbody%20onload=alert(document.cookie)%3E.jpg';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<body onload=alert\(document.cookie\)>",
   extra_check:make_list("file not found", ".jpg")))
{
  security_message(http_port);
  exit(0);
}
