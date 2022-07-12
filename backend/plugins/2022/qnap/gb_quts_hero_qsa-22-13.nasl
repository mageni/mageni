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

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170124");
  script_version("2022-05-30T13:08:16+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:37:36 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-30 09:06:24 +0000 (Mon, 30 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 20:16:00 +0000 (Fri, 13 May 2022)");

  script_cve_id("CVE-2021-38693");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Path Traversal Vulnerability (QSA-22-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A path traversal vulnerability in thttpd has been reported to
  affect QNAP devices running QuTS hero.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows attackers to access and
  read sensitive data.");

  script_tag(name:"solution", value:"Update to version h4.5.4.1951 build 20220218, 5.0.0.1949 build
  20220215 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-13");

  exit(0);

}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit(0);

if ( version_is_less( version:version, test_version:"h4.5.4_20220218" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"h4.5.4_20220218" );
  security_message( port:0, data:report );
  exit(0);
}

if ( version_in_range_exclusive( version:version, test_version_lo:"h5.0.0", test_version_up:"h5.0.0_20220215" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"h5.0.0_20220215" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
