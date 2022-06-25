###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_agfeo_smarthome_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# AGFEO SmartHome Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:agfeo:smarthome";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106965");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-18 15:36:38 +0700 (Tue, 18 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AGFEO SmartHome Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_agfeo_smarthome_detect.nasl");
  script_mandatory_keys("agfeo_smarthome/detected");

  script_tag(name:"summary", value:"AGFEO SmartHome is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"AGFEO SmartHome is prone to multiple vulnerabilities:

  - Unauthenticated access to web services and authentication bypass

  - Unauthenticated access to configuration ports

  - Hardcoded cryptographic keys

  - Multiple reflected cross site scripting (XSS) vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"AGFEO SmartHome on ES 5/6/7 prior to version 1.12c");

  script_tag(name:"solution", value:"Upgrade to version 1.12c or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20170712-0_AGFEO_Smart_Home_Multiple_critical_vulnerabilities_v10.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "1.12c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.12c");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
