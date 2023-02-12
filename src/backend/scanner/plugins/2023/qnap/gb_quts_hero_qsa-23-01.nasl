# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170302");
  script_version("2023-02-02T10:09:00+0000");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-01-31 13:20:35 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-27596");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Code Injection Vulnerability (QSA-23-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to a code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows remote attackers to inject
  malicious code.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.0.1 prior to h5.0.1.2248
  build 20221215.");

  script_tag(name:"solution", value:"Update to version QuTS hero h5.0.1 build 20221215 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-01");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/quts_hero/h5.0.1.2248/20221215");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( version_in_range_exclusive( version:version, test_version_lo:"h5.0.1", test_version_up:"h5.0.1_20221215" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"h5.0.1_20221215" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
