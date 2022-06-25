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
  script_oid("1.3.6.1.4.1.25623.1.0.113705");
  script_version("2020-06-17T11:22:48+0000");
  script_tag(name:"last_modification", value:"2020-06-18 10:16:17 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-17 11:12:33 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-14093", "CVE-2020-14154");

  script_name("Mutt < 1.14.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_mutt_detect.nasl");
  script_mandatory_keys("mutt/detected");

  script_tag(name:"summary", value:"Mutt is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Mutt allows an IMAP fcc/postpone man-in-the-middle attack via a PREAUTH response. (CVE-2020-14093)

  - Mutt proceeds with a connection even if, in response to a GnuTLS certificate prompt,
    the user rejects an expired intermediate certificate. (CVE-2020-14154)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  bypass authentication or read sensitive information.");

  script_tag(name:"affected", value:"Mutt through version 1.14.2.");

  script_tag(name:"solution", value:"Update to version 1.14.3 or later.");

  script_xref(name:"URL", value:"http://lists.mutt.org/pipermail/mutt-announce/Week-of-Mon-20200608/000022.html");

  exit(0);
}

CPE = "cpe:/a:mutt:mutt";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.14.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.14.3", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
