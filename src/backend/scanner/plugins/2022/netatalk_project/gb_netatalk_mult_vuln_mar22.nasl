# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:netatalk_project:netatalk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113948");
  script_version("2022-04-25T15:25:54+0000");
  script_tag(name:"last_modification", value:"2022-04-25 15:25:54 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-25 14:38:33 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 12:48:00 +0000 (Thu, 27 May 2021)");
  script_cve_id("CVE-2021-31439", "CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122",
                "CVE-2022-23123", "CVE-2022-23124", "CVE-2022-23125");
  script_name("Netatalk < 3.1.13 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_netatalk_asip_afp_detect.nasl");
  script_mandatory_keys("netatalk/detected");

  script_tag(name:"summary", value:"Netatalk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  # TODO: Update the "unspecified" vulnerabilities text below once the CVE entries got published
  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-31439: A heap-based buffer overflow remote code execution (RCE) vulnerability

  - CVE-2022-0194, CVE-2022-23121, CVE-2022-23122, CVE-2022-23123, CVE-2022-23124, CVE-2022-23125:
  Multiple (currently) unspecified vulnerabilities");

  script_tag(name:"affected", value:"Netatalk versions before 3.1.13.");

  script_tag(name:"solution", value:"Update to version 3.1.13 or later.");

  script_xref(name:"URL", value:"https://netatalk.sourceforge.io/3.1/ReleaseNotes3.1.13.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.1.13" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.13" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
