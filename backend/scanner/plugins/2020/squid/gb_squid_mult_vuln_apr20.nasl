# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113674");
  script_version("2020-04-14T09:57:14+0000");
  script_tag(name:"last_modification", value:"2020-04-17 09:53:31 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-14 09:27:08 +0000 (Tue, 14 Apr 2020)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-12521", "CVE-2019-12522", "CVE-2019-12524");

  script_name("Squid <= 4.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Denial of Service vulnerability due to an off-by-one bug while parsing ESI

  - Privilege Escalation when exiting Squid after it has been run as root

  - Information Disclosure due to a lack of access control when requesting encrypted URLs");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application,
  access sensitive information or even get complete control over the target system.");

  script_tag(name:"affected", value:"Squid through version 4.7.");

  script_tag(name:"solution", value:"No known solution is available as of 16th April, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12521.txt");
  script_xref(name:"URL", value:"https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12522.txt");
  script_xref(name:"URL", value:"https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12524.txt");

  exit(0);
}

CPE = "cpe:/a:squid-cache:squid";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "No known solution", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

#nb: As we cannot be sure if higher versions are still vulnerable, no EXIT_NOTVULN
exit( 0 );
