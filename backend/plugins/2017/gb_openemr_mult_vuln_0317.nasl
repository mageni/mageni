###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_mult_vuln_0317.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# OpenEMR < 5.0.0 Patch 2 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:open-emr:openemr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112148");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-06 13:27:26 +0100 (Wed, 06 Dec 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 5.0.0 Patch 2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR 5.0.0 prior to patch 2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenEMR is prone to the following vulnerabilities:

1. OS Command Injection
  Any OS commands can be injected by an authenticated attacker with any role.
  This is a serious vulnerability as the chance for the system to be fully compromised is very high.

2. Reflected Cross Site Scripting
  This vulnerability allows an attacker to inject malicious client side
scripting which will be executed in the browser of users if they visit the
manipulated site. There are different issues affecting various components.");

  script_tag(name:"impact", value:"By exploiting the vulnerability, an attacker can
fully compromise the web server which has OpenEMR installed. Potentially
sensitive health care and medical data might get exposed through this attack.");

  script_tag(name:"affected", value:"OpenEMR prior to 5.0.0 patch 2.");

  script_tag(name:"solution", value:"Upgrade to OpenEMR 5.0.0 patch 2 or higher.");


  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Dec/16");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.0-2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.0 Patch 2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
