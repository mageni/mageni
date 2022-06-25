###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoneminder_mult_vuln_mar17.nasl 13479 2019-02-05 16:04:12Z asteins $
#
# ZoneMinder <= 1.30.1 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112507");
  script_version("$Revision: 13479 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 17:04:12 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-05 16:56:11 +0100 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-10201", "CVE-2016-10202", "CVE-2016-10203", "CVE-2016-10204", "CVE-2016-10205", "CVE-2016-10206");
  script_bugtraq_id(97116, 97114);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder <= 1.30.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple cross-site scripting (XSS) vulnerabilities.

  - Session fixation.

  - Cross-site request forgery.

  - SQL injection.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  HTML or JavaScript code via multiple parameters, to hijack web sessions, to execute arbitrary SQL
  commands or to have other unspecified impact on the application and its host system.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update ZoneMinder to the latest available version.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/02/05/1");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/releases");

  exit(0);
}

CPE = "cpe:/a:zoneminder:zoneminder";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less_equal(version: version, test_version: "1.30.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Update to the latest available version");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
