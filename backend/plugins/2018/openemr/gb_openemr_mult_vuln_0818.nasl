###############################################################################
# OpenVAS Vulnerability Test
#
# OpenEMR < 5.0.1.4 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112356");
  script_version("2019-05-03T13:51:56+0000");
  script_cve_id("CVE-2018-15139", "CVE-2018-15140", "CVE-2018-15141",
  "CVE-2018-15142", "CVE-2018-15143", "CVE-2018-15144", "CVE-2018-15145",
  "CVE-2018-15146", "CVE-2018-15147", "CVE-2018-15148", "CVE-2018-15149",
  "CVE-2018-15150", "CVE-2018-15151", "CVE-2018-15152", "CVE-2018-15153",
  "CVE-2018-15154", "CVE-2018-15155", "CVE-2018-15156");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-14 09:22:33 +0200 (Tue, 14 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenEMR < 5.0.1.4 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running OpenEMR and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws consist of multiple SQL injection vulnerabilities,
  directory traversal vulnerabilities, OS command injection vulnerabilities, an authentication bypass vulnerability
  and an unrestricted file upload vulnerability.");

  script_tag(name:"affected", value:"OpenEMR versions before 5.0.1.4");

  script_tag(name:"solution", value:"Upgrade to OpenEMR version 5.0.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.databreaches.net/openemr-patches-serious-vulnerabilities-uncovered-by-project-insecurity/");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/1757/commits/c2808a0493243f618bbbb3459af23c7da3dc5485");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/1765/files");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/1758/files");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/1757/files");
  script_xref(name:"URL", value:"https://insecurity.sh/reports/openemr.pdf");
  script_xref(name:"URL", value:"https://www.open-emr.org/wiki/index.php/OpenEMR_Patches");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed", "openemr/version");
  script_require_ports("Services/www", 80);

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

CPE = "cpe:/a:open-emr:openemr";

if( ! port = get_app_port( cpe: CPE ) ) {
  exit( 0 );
}

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) {
  exit( 0 );
}
version = infos[ 'version' ];
location = infos[ 'location' ];

if( version_is_less( version: version, test_version: "5.0.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.1.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
