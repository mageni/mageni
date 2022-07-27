###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_mult_vuln_july16_lin.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# WordPress Multiple Vulnerabilities July16 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808256");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-5832", "CVE-2016-5833", "CVE-2016-5834", "CVE-2016-5835",
                "CVE-2016-5836", "CVE-2016-5837", "CVE-2016-5838", "CVE-2016-5839");
  script_bugtraq_id(91362, 91368, 91366, 91363, 91365, 91367, 91364);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-20 15:37:55 +0530 (Wed, 20 Jul 2016)");
  script_name("WordPress Multiple Vulnerabilities July16 (Linux)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insufficient validation of user supplied input via attachment name in
    the column_title function in 'wp-admin/includes/class-wp-media-list-table.php'
    script.

  - An error related to 'wp-admin/includes/ajax-actions.php' and
    'wp-admin/revision.php' scripts.

  - An error in customizer.

  - An insufficient validation of user supplied input via attachment name in
    the wp_get_attachment_link function in 'wp-includes/post-template.php'
    script.

  - An error in 'oEmbed' protocol implementation.

  - Other multiple unspecified errors.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to inject arbitrary web script or HTML, obtain sensitive
  information, bypass intended redirection restrictions, cause a denial
  of service and bypass intended password-change restrictions.");

  script_tag(name:"affected", value:"WordPress versions prior to 4.5.3 on Linux.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 4.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://wordpress.org/news/2016/06/wordpress-4-5-3");
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

if(version_is_less(version:wpVer, test_version:"4.5.3"))
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"4.5.3");
  security_message(data:report, port:wpPort);
  exit(0);
}
