###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_esc_sql_fun_vuln_nov17_lin.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# WordPress 'esc_sql' Function SQL Injection Vulnerability - Nov 2017 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811888");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-16510");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-02 10:53:57 +0530 (Thu, 02 Nov 2017)");
  script_name("WordPress 'esc_sql' Function SQL Injection Vulnerability - Nov 2017 (Linux)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to an sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because '$wpdb->prepare'
  function can create unexpected and unsafe queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary commands.");

  script_tag(name:"affected", value:"WordPress versions 4.8.2 and earlier");

  script_tag(name:"solution", value:"Upgrade to WordPress version 4.8.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://wordpress.org/news/2017/10/wordpress-4-8-3-security-release");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wordPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, port:wordPort)){
  exit(0);
}

if(version_is_less(version:vers, test_version:"4.8.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.3");
  security_message(data:report, port:wordPort);
  exit(0);
}
exit(0);
