###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sugarcrm_mult_vuln_jun16.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# SugarCRM Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:sugarcrm:sugarcrm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106123");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-08 15:37:30 +0700 (Fri, 08 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SugarCRM Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_detect.nasl");
  script_mandatory_keys("sugarcrm/installed");

  script_tag(name:"summary", value:"SugarCRM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SugarCRM is prone to multiple vulnerabilities:

The application fails to properly check whether the user has administrator privileges within the following
scripts: /modules/Administration/ImportCustomFieldStructure.php, /modules/Administration/UpgradeWizard_commit.php,
/modules/Connectors/controller.php ('RunTest' action)

The 'override_value_to_string_recursive2()' function is being used to save an array into a configuration file
with a .php extension. However, this function does not properly escape key names, and this can be exploited
to inject and execute arbitrary PHP code.

User input passed through the 'type_module' request parameter isn't properly sanitized before being used
to instantiate a new DashletRssFeedTitle object, and this could be exploited to carry out certain attacks
because of the DashletRssFeedTitle::readFeed() method (user input passed directly to the 'fopen()' function).");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary OS commands.");

  script_tag(name:"affected", value:"Version <= 6.5.18");

  script_tag(name:"solution", value:"Update to 6.5.19 or newer.");

  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2016-04");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2016-05");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2016-06");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.5.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.19");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
