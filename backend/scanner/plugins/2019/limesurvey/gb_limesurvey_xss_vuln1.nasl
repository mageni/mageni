##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limesurvey_xss_vuln1.nasl 13109 2019-01-17 07:42:10Z ckuersteiner $
#
# LimeSurvey < 3.15.6 XSS Vulnerability
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

CPE = "cpe:/a:limesurvey:limesurvey";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141880");
  script_version("$Revision: 13109 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-17 08:42:10 +0100 (Thu, 17 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-16 17:07:47 +0700 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-20322");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 3.15.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey contains an XSS vulnerability while uploading a ZIP file, resulting
in JavaScript code execution against LimeSurvey admins.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 3.15.6 or later.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/bfee69edaa0b90f97dc2d8fab09a87958cb32405");
  script_xref(name:"URL", value:"https://bugs.limesurvey.org/view.php?id=14376");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.15.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.15.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
