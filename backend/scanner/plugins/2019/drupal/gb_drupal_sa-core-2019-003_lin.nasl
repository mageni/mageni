# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142013");
  script_version("$Revision: 13949 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 08:26:12 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-21 08:59:15 +0700 (Thu, 21 Feb 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-6340");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal RCE Vulnerability (SA-CORE-2019-003) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Some field types do not properly sanitize data from non-form sources. This
can lead to arbitrary PHP code execution in some cases.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A site is only affected by this if one of the following conditions is met:

  - The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests,
    or

  - the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web
    Services in Drupal 7.");

  script_tag(name:"affected", value:"Drupal 8.5.x and 8.6.x.");

  script_tag(name:"solution", value:"Update to version 8.5.11, 8.6.10 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-003");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.6", test_version2: "8.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.10");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
