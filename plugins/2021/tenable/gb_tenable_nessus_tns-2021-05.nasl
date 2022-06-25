# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118007");
  script_version("2021-04-08T09:30:30+0000");
  script_tag(name:"last_modification", value:"2021-04-08 09:30:30 +0000 (Thu, 08 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-07 15:50:26 +0200 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-3449", "CVE-2021-3450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus <= 8.13.1 Multiple Third-party Vulnerabilities (TNS-2021-05)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple third-party vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"One of the third-party components (OpenSSL) was found to contain
  vulnerabilities, and updated versions have been made available by the providers.

  Nessus 8.13.2 updates OpenSSL to version 1.1.1k to address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus up to and including version 8.13.1.");

  script_tag(name:"solution", value:"Update to version 8.13.2 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2021-05");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"8.13.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.13.2", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
