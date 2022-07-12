###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_mult_vuln_may17_lin.nasl 11816 2018-10-10 10:42:56Z mmartin $
#
# WordPress Multiple Vulnerabilities - May17 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811046");
  script_version("$Revision: 11816 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 12:42:56 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-19 10:56:22 +0530 (Fri, 19 May 2017)");
  script_name("WordPress Multiple Vulnerabilities - May17 (Linux)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insufficient redirect validation in the HTTP class.

  - An improper handling of post meta data values in the XML-RPC API.

  - The lack of capability checks for post meta data in the XML-RPC API.

  - A cross site request forgery (CSRF)  vulnerability in the filesystem
    credentials dialog.

  - A cross-site scripting (XSS) vulnerability when attempting to upload very
    large files.

  - A cross-site scripting (XSS) vulnerability related to the Customizer.");

  script_tag(name:"impact", value:"Successfully exploiting will allow remote
  attacker to conduct cross site request forgery (CSRF) attacks, cross-site
  scripting (XSS) attacks and have other some unspecified impact.");

  script_tag(name:"affected", value:"WordPress versions 4.7.4 and prior on
  Linux.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 4.7.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://wordpress.org/news/2017/05/wordpress-4-7-5");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org");
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

if(version_is_less(version:wpVer, test_version:"4.7.5"))
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"4.7.5");
  security_message(data:report, port:wpPort);
  exit(0);
}
