###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_reflected_xss_vuln_may16_lin.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# WordPress Core Reflected XSS Vulnerability May16 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808037");
  script_version("$Revision: 12455 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-17 12:35:57 +0530 (Tue, 17 May 2016)");
  script_name("WordPress Core Reflected XSS Vulnerability May16 (Linux)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to reflected xss vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  MediaElement.js library used for media players.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to execute arbitrary script code in a user's browser
  session within the trust relationship.");

  script_tag(name:"affected", value:"WordPress versions 4.2.x through 4.5.1 on
  Linux.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 4.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://wordpress.org/news/2016/05/wordpress-4-5-2");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!wpVer = get_app_version(cpe:CPE, port:wpPort)){
  exit(0);
}

if(version_in_range(version:wpVer, test_version:"4.2", test_version2:"4.5.1"))
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"4.5.2");
  security_message(data:report, port:wpPort);
  exit(0);
}
