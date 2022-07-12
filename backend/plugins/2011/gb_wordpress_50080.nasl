###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_50080.nasl 10235 2018-06-18 13:14:33Z cfischer $
#
# WordPress Light Post Plugin 'abspath' Parameter Remote File Include Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103300");
  script_version("$Revision: 10235 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-18 15:14:33 +0200 (Mon, 18 Jun 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 12:50:33 +0200 (Fri, 14 Oct 2011)");
  script_bugtraq_id(50080);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Light Post Plugin 'abspath' Parameter Remote File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50080");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset/437217/light-post/trunk/wp-light-post.php?old=416259&old_path=light-post%2Ftrunk%2Fwp-light-post.php");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/light-post/changelog/");
  script_xref(name:"URL", value:"http://www.wordpress.org");

  script_tag(name:"summary", value:"The Light Post WordPress Plugin is prone to a remote file-include
  vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to compromise the
  application and the underlying system. Other attacks are also possible.");

  script_tag(name:"affected", value:"Light Post Plugin 1.4 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

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

  url = string(dir, "/wp-content/plugins/light-post/wp-light-post.php?abspath=/", files[file], "%00");
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
