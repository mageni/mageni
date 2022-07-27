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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142138");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-13 11:33:01 +0700 (Wed, 13 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-9711", "CVE-2019-9712", "CVE-2019-9713", "CVE-2019-9714");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Joomla! < 3.9.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla! is prone to multiple vulnerabilities:

  - The item_title layout in edit views lacks escaping, leading to XSS. (CVE-2019-9711)

  - The JSON handler in com_config lacks input validation, leading to XSS. (CVE-2019-9712)

  - The sample data plugins lack ACL checks, allowing unauthorized access. (CVE-2019-9713)

  - The media form field lacks escaping, leading to XSS. (CVE-2019-9714)");

  script_tag(name:"affected", value:"Joomla! CMS versions 3.0.0 through 3.9.3.");

  script_tag(name:"solution", value:"Update to version 3.9.4 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/773-20190302-core-xss-in-item-title-layout");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/772-20190301-core-xss-in-com-config-json-handler");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/775-20190304-core-missing-acl-check-in-sample-data-plugins");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/774-20190303-core-xss-in-media-form-field");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.4", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
