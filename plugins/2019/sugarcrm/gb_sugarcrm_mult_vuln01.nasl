###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sugarcrm_mult_vuln01.nasl 12923 2019-01-02 08:18:39Z ckuersteiner $
#
# SugarCRM 7.x Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141815");
  script_version("$Revision: 12923 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-02 09:18:39 +0100 (Wed, 02 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-02 14:24:22 +0700 (Wed, 02 Jan 2019)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SugarCRM 7.x Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_detect.nasl");
  script_mandatory_keys("sugarcrm/installed");

  script_tag(name:"summary", value:"SugarCRM is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"SugarCRM is prone to multiple vulnerabilities:

  - Remote Code Execution vulnerability in a component of the Workflow module

  - SQL injection in the SugarCRM SOAP API related to portal users

  - SSRF attack vector (and related XSS and CSRF) in the connectors framework

  - Potential path traversal attacks where user-controllable input is being used to construct file paths which are
    being used by include or require PHP statements.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"SugarCRM 7.9 and 7.10");

  script_tag(name:"solution", value:"Update to version 7.9.4.0, 7.11.0.0 or later.");

  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-001/");
  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-003/");
  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-004/");
  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-005/");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2018-02");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2018-03");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2018-04");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^7\.9\.") {
  if (version_is_less(version: version, test_version: "7.9.4.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.9.4.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^7\.10\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.11.0.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
