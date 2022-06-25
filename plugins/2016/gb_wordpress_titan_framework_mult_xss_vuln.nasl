###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_titan_framework_mult_xss_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Wordpress Titan Framework Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807057");
  script_version("$Revision: 12096 $");
  script_cve_id("CVE-2014-6444");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-05 09:30:21 +0530 (Fri, 05 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Wordpress Titan Framework Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  Titan Framework plugin and is prone to multiple cross site scripting
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of user supplied input via 't' parameter to
    'iframe-googlefont-preview.php' script.

  - An insufficient validation of user supplied input via 'text' parameter
    to 'iframe-font-preview.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"Wordpress Titan Framework plugin version
  before 1.6");

  script_tag(name:"solution", value:"Upgrade to version 1.6 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8233");
  script_xref(name:"URL", value:"https://research.g0blin.co.uk/cve-2014-6444");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/titan-framework");
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

url = dir + '/wp-content/plugins/titan-framework/iframe-font-preview.php?text=<script>alert(document.cookie);</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document.cookie\);</script>",
  extra_check:make_list("titan-framework", "wordpress")))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
