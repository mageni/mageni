###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_views_mod_access_bypass_vuln_lin.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Drupal 'Views' Module Access Bypass Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807887");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-6212");
  script_bugtraq_id(91230);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-27 10:06:16 +0530 (Tue, 27 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal 'Views' Module Access Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists due to error within the 'Views'
  module, where users without the 'View content count' permission can see the
  number of hits collected by the Statistics module for results in the view.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass access restrictions and see statistics information.");

  script_tag(name:"affected", value:"Drupal core 8.x versions prior to 8.1.3");

  script_tag(name:"solution", value:"Upgrade to version 8.1.3 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!drupalPort= get_app_port(cpe:CPE)){
  exit(0);
}

if(!drupalVer = get_app_version(cpe:CPE, port:drupalPort, version_regex:"^[0-9]\.[0-9]+")){
  exit(0);
}

if(version_in_range(version:drupalVer, test_version:"8.0", test_version2:"8.1.2"))
{
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:"8.1.3");
  security_message(data:report, port:drupalPort);
  exit(0);
}
