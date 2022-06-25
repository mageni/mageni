##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_gdpr_compliance_priv_esc_vuln.nasl 13517 2019-02-07 07:51:12Z mmartin $
#
# WordPress WP GDPR Compliance Plugin < 1.4.3 Privilege Escalation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141674");
  script_version("$Revision: 13517 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-07 08:51:12 +0100 (Thu, 07 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-13 09:52:45 +0700 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-19207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP GDPR Compliance Plugin < 1.4.3 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin GDPR Compliance allows unauthenticated users to execute
any action and update any database value.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress WP GDPR Compliance plugin prior to version 1.4.3.");

  script_tag(name:"solution", value:"Update to version 1.4.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2018/11/privilege-escalation-flaw-in-wp-gdpr-compliance-plugin-exploited-in-the-wild/");
  script_xref(name:"URL", value:"https://wordpress.org/support/topic/important-update-to-1-4-3-immediately/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/wp-gdpr-compliance/readme.txt");

if ("WP GDPR Compliance" >< res && "Changelog" >< res) {
  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    if (version_is_less(version: vers[1], test_version: "1.4.3")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.4.3");
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
