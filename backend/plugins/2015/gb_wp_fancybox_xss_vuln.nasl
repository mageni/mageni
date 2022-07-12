###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_fancybox_xss_vuln.nasl 11890 2018-10-12 16:13:30Z cfischer $
#
# FancyBox for Wordpress XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105958");
  script_version("$Revision: 11890 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 18:13:30 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-02 09:33:03 +0700 (Mon, 02 Mar 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-1494");
  script_bugtraq_id(72506);

  script_name("FancyBox for Wordpress XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"FancyBox for Wordpress is prone to a XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to detect the version of FancyBox plugin.");

  script_tag(name:"insight", value:"The FancyBox for WordPress plugin before 3.0.3 does not
  properly restrict access, which allows remote attackers to conduct XSS attacks via the mfbfw parameter
  in an update action to wp-admin/admin-post.php.");

  script_tag(name:"impact", value:"Remote attackers may be able to inject arbitrary web script
  or HTML.");

  script_tag(name:"affected", value:"FancyBox for Wordpress 3.0.2 and below");

  script_tag(name:"solution", value:"Upgrade to FancyBox for Wordpress 3.0.3 or later.");

  script_xref(name:"URL", value:"http://blog.sucuri.net/2015/02/zero-day-in-the-fancybox-for-wordpress-plugin.html");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36087/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/fancybox-for-wordpress/changelog/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + 'wp-content/plugins/fancybox-for-wordpress/readme.txt';

req = http_get(port:port, item:url);
res = http_keepalive_send_recv(port:port, data:req);

if (res && res =~ 'HTTP/1.. 200') {
  version = eregmatch(pattern:'Stable tag: ([0-9.]+)', string:res);

  if (version && version_is_less(version:version[1], test_version:"3.0.3")) {
    report = 'Installed version: ' + version[1] + '\n' +
             'Fixed version:     3.0.3\n';
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
