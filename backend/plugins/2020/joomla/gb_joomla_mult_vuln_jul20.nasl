# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113726");
  script_version("2020-07-20T11:33:10+0000");
  script_tag(name:"last_modification", value:"2020-07-21 10:01:45 +0000 (Tue, 21 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-20 11:25:20 +0000 (Mon, 20 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15695", "CVE-2020-15696", "CVE-2020-15697", "CVE-2020-15698", "CVE-2020-15699", "CVE-2020-15700");

  script_name("Joomla! <= 3.9.19 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A missing token check in the remove request section of com_privacy causes a CSRF vulnerability. (CVE-2020-15695)

  - Lack of input filtering and escaping allows XSS attacks in mod_random_image. (CVE-2020-15696)

  - Internal read-only fields in the User table class could be modified by users. (CVE-2020-15697)

  - Inadequate filtering on the system information screen could expose Redis or proxy credentials. (CVE-2020-15698)

  - Missing validation checks on the usergroups table object can result in a broken site configuration. (CVE-2020-15699)

  - A missing token check in the ajax_install endpoint of com_installer causes a CSRF vulnerability. (CVE-2020-15700)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  read sensitive information, inject arbitrary HTML and JavaScript into the site
  or perform actions in the context of another use.");

  script_tag(name:"affected", value:"Joomla! through version 3.9.19.");

  script_tag(name:"solution", value:"Update to version 3.9.20.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/820-20200703-core-csrf-in-com-privacy-remove-request-feature.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/822-20200705-core-escape-mod-random-image-link.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/821-20200704-core-variable-tampering-via-user-table-class.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/823-20200706-core-system-information-screen-could-expose-redis-or-proxy-credentials.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/819-20200702-core-missing-checks-can-lead-to-a-broken-usergroups-table-record.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/818-20200701-core-csrf-in-com-installer-ajax-install-endpoint.html");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.9.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.20", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
