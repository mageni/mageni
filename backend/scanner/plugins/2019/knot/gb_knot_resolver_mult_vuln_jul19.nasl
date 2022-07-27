# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113449");
  script_version("2019-07-24T12:19:51+0000");
  script_tag(name:"last_modification", value:"2019-07-24 12:19:51 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-22 15:39:45 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10190", "CVE-2019-10191");

  script_name("Knot Resolver < 4.1.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_knot_resolver_detect.nasl");
  script_mandatory_keys("knot/resolver/detected");

  script_tag(name:"summary", value:"Knot Resolver is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - The NXDOMAIN answer could get passed through to the client
    if its DNSSEC validation failed, instead of sending a SERVFAIL packet.

  - Remote attackers can downgrade DNSSEC-secure domains, to an DNSSEC-insecure state,
    opening a possibility of domain hijacking using attacks against insecure DNS protocol.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to poison the DNS cache or hijack the domain.");
  script_tag(name:"affected", value:"knot resolver through version 4.0.0.");
  script_tag(name:"solution", value:"Update to version 4.1.0.");

  script_xref(name:"URL", value:"https://www.knot-resolver.cz/2019-07-10-knot-resolver-4.1.0.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-10190");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-10191");

  exit(0);
}

CPE = "cpe:/a:knot-resolver:knot_resolver";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
