###############################################################################
# OpenVAS Vulnerability Test
# $Id: WordPress_35755.nasl 14012 2019-03-06 09:13:44Z cfischer $
#
# WordPress Comment Author URI Cross-Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100239");
  script_version("$Revision: 14012 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 10:13:44 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-22 19:53:45 +0200 (Wed, 22 Jul 2009)");
  script_cve_id("CVE-2009-2851");
  script_bugtraq_id(35755);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Comment Author URI Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
  for details.");

  script_tag(name:"summary", value:"WordPress is prone to a cross-site scripting vulnerability because the
  application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may help the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to WordPress 2.8.2 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35755");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=278492");
  script_xref(name:"URL", value:"http://wordpress.org/development/2009/07/wordpress-2-8-2/");
  script_xref(name:"URL", value:"http://wordpress.org/");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version: vers, test_version: "2.8.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.8.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);