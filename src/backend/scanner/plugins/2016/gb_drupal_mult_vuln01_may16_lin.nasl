###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_mult_vuln01_may16_lin.nasl 11811 2018-10-10 09:55:00Z asteins $
#
# Drupal Multiple Vulnerabilities01- May16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808043");
  script_version("$Revision: 11811 $");
  script_cve_id("CVE-2016-3171", "CVE-2016-3167", "CVE-2016-3165", "CVE-2016-3166");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 11:55:00 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-18 15:57:00 +0530 (Wed, 18 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Multiple Vulnerabilities01- May16 (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exixts due to,

  - An error in session data truncation which can lead to unserialization of
    user provided data

  - The 'drupal_goto' function improperly decodes the contents of
    '$_REQUEST['destination']' before using it.

  - Form API ignores access restrictions on submit buttons.

  - An error in the 'drupal_set_header' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause remote code execution, initiate a redirect to an arbitrary
  external URL, bypass security restrictions and inject arbitrary HTTP
  headers.");

  script_tag(name:"affected", value:"Drupal 6.x before 6.38 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 6.38 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.drupal.org");
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

if(version_in_range(version:drupalVer, test_version:"6.0", test_version2:"6.37"))
{
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:"6.38");
  security_message(data:report, port:drupalPort);
  exit(0);
}
