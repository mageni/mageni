##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magento_file_disc_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Magento Config File Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140460");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-01 11:50:25 +0700 (Wed, 01 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Magento Config File Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl", "secpod_apache_detect.nasl");
  script_mandatory_keys("magento/installed");
  script_exclude_keys("apache/installed");

  script_tag(name:"summary", value:"Magento installed on other web servers than Apache may leak the config
file.");

  script_tag(name:"insight", value:"Magento stores its configuration in a file local.xml, stored in the webroot
under app/etc/local.xml. As it is an xml file by default a web server will not parse it in any way, but directly
expose it to users.

Magento protects against this by shipping an .htaccess file that blocks access to that directory. However that is
not a sufficient protection. .htaccess files are specific to the Apache web server. Other web servers like nginx
don't support .htaccess. This leaves users with a situation where installation on any web server other than Apache
will by default lead to a configuration where the local.xml file can be downloaded by anyone over the Internet.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Set the permissions on app/etc/local.xml in your web server
configuration.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q4/141");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/app/etc/local.xml";

if (http_vuln_check(port: port, url: url, pattern: "<username>.*</username>", check_header: TRUE,
                    extra_check: "<password>.*</password>")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
