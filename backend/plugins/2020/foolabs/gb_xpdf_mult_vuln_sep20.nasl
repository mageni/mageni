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
  script_oid("1.3.6.1.4.1.25623.1.0.113752");
  script_version("2020-09-08T08:43:48+0000");
  script_tag(name:"last_modification", value:"2020-09-08 09:56:35 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-08 08:03:57 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-24996", "CVE-2020-24999");

  script_name("Xpdf <= 4.02 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_xpdf_detect.nasl");
  script_mandatory_keys("Xpdf/Linux/Ver");

  script_tag(name:"summary", value:"Xpdf is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Denial of service (DoS) in the pdftohtml binary because of
    an invalid memory access in the function TextString::~TextString() located in Catalog.cc. (CVE-2020-24996)

  - Denial of service (DoS) in the pdftohtml binary because of
    an invalid memory access in the function fprintf located in Error.cc. (CVE-2020-24999)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");

  script_tag(name:"affected", value:"Xpdf through version 4.02.");

  script_tag(name:"solution", value:"No known solution is available as of 08th September, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=42028");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=42029");

  exit(0);
}

CPE = "cpe:/a:foolabs:xpdf";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.02" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
