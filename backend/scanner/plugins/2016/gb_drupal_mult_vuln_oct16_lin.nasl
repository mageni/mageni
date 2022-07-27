###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_mult_vuln_oct16_lin.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Drupal Multiple Vulnerabilities- Oct16 (Linux)
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809433");
  script_version("$Revision: 12363 $");
  script_cve_id("CVE-2016-7571", "CVE-2016-7572", "CVE-2016-7570");
  script_bugtraq_id(93101);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-07 10:50:13 +0530 (Fri, 07 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Multiple Vulnerabilities- Oct16 (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exixts due to,

  - The system.temporary route not properly check for 'Export configuration'
    permission.

  - Users without 'Administer comments' set comment visibility on nodes.

  - Cross-site Scripting in http exceptions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to set the visibility of comments for arbitrary nodes
  or to bypass intended access restrictions and read a full config export
  or to inject arbitrary web script.");

  script_tag(name:"affected", value:"Drupal core 8.x versions prior to 8.1.10");

  script_tag(name:"solution", value:"Upgrade to version 8.1.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-004");

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

if(version_in_range(version:drupalVer, test_version:"8.0", test_version2:"8.1.9"))
{
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:"8.1.10");
  security_message(data:report, port:drupalPort);
  exit(0);
}
