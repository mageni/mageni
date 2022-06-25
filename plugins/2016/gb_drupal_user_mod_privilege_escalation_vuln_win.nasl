###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_user_mod_privilege_escalation_vuln_win.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Drupal 'User' Module Privilege Escalation Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807884");
  script_version("$Revision: 12338 $");
  script_cve_id("CVE-2016-6211");
  script_bugtraq_id(91230);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-26 14:40:24 +0530 (Mon, 26 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Drupal 'User' Module Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists due to error within the 'User'
  module, where a specific code can trigger a rebuild of the user profile form
  and a registered user can be granted all user roles on the site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to administrative privileges.");

  script_tag(name:"affected", value:"Drupal core 7.x versions prior to 7.44");

  script_tag(name:"solution", value:"Upgrade to version 7.44 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");
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

if(version_in_range(version:drupalVer, test_version:"7.0", test_version2:"7.43"))
{
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:"7.44");
  security_message(data:report, port:drupalPort);
  exit(0);
}
