# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:formalms:formalms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126193");
  script_version("2022-11-03T10:20:15+0000");
  script_tag(name:"last_modification", value:"2022-11-03 10:20:15 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-02 09:23:33 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-41679", "CVE-2022-41680", "CVE-2022-41681", "CVE-2022-42923",
                "CVE-2022-42924", "CVE-2022-42925");

  script_name("Forma LMS <= 3.1.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_formalms_http_detect.nasl");
  script_mandatory_keys("formalms/detected");

  script_tag(name:"summary", value:"Forma LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-41679: A stored cross-site scripting vulnerability through the back_url parameter in
  appLms/index.php?modname=faq&op=play function.

  - CVE-2022-41680: A SQL injection vulnerability through the search[value] parameter in the
  appLms/ajax.server.php?r=mycertificate/getMyCertificates function.

  - CVE-2022-41681: Forma LMS could allow an authenticated attacker to privilege escalate in order
  to upload a Zip file through the SCORM importer feature.

  - CVE-2022-42923: A SQL injection vulnerability through the id parameter in the
  appCore/index.php?r=adm/mediagallery/delete function.

  - CVE-2022-42924: A SQL injection vulnerability through the dyn_filter parameter in the
  appLms/ajax.adm_server.php?r=widget/userselector/getusertabledata function.

  - CVE-2022-42925: Forma LMS could allow an authenticated attacker to privilege escalate in order
  to upload a Zip file through the plugin upload component.");

  script_tag(name:"affected", value:"Forma LMS version 3.1.0 and prior.");

  script_tag(name:"solution", value:"Update to version 3.2.1 or later.");

  script_xref(name:"URL", value:"https://www.incibe-cert.es/en/early-warning/security-advisories/multiple-vulnerabilities-forma-lms");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "3.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
