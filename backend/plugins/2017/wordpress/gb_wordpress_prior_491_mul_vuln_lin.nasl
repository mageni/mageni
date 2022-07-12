###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_prior_491_mul_vuln_lin.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# WordPress < 4.9.1 Multiple Vulnerabilities (Linux)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112146");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-04 14:36:33 +0100 (Mon, 04 Dec 2017)");
  script_cve_id("CVE-2017-17091", "CVE-2017-17092", "CVE-2017-17093", "CVE-2017-17094");

  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("WordPress < 4.9.1 Multiple Vulnerabilities (Linux)");
  script_tag(name:"summary", value:"WordPress prior to 4.9.1 is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress before 4.9.1 is prone to the following security vulnerabilities:

  - wp-admin/user-new.php sets the newbloguser key to a string that can be directly derived from the user ID,
which allows remote attackers to bypass intended access restrictions by entering this string. (CVE-2017-17091)

  - wp-includes/functions.php does not require the unfiltered_html capability for upload of .js files,
which might allow remote attackers to conduct XSS attacks via a crafted file. (CVE-2017-17092)

  - wp-includes/general-template.php does not properly restrict the lang attribute of an HTML element,
which might allow attackers to conduct XSS attacks via the language setting of a site. (CVE-2017-17093)

  - wp-includes/feed.php does not properly restrict enclosures in RSS and Atom fields,
which might allow attackers to conduct XSS attacks via a crafted URL. (CVE-2017-17094)");

  script_tag(name:"impact", value:"An attacker may leverage these issues to bypass access restrictions or conduct XSS via specific vectors.");

  script_tag(name:"affected", value:"WordPress prior to version 4.9.1.");

  script_tag(name:"solution", value:"Update to WordPress 4.9.1 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/");
  script_xref(name:"URL", value:"https://codex.wordpress.org/Version_4.9.1");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_is_less(version:ver, test_version:"4.9.1"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"4.9.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
