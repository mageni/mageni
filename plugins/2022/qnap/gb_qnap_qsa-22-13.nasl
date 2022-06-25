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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170099");
  script_version("2022-05-09T09:41:30+0000");
  script_tag(name:"last_modification", value:"2022-05-09 10:04:03 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-09 09:08:13 +0000 (Mon, 09 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-38693");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Path Traversal Vulnerability (QSA-22-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A path traversal vulnerability in thttpd has been reported to
  affect QNAP devices running QTS.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows attackers to access and
  read sensitive data.");

  script_tag(name:"solution", value:"Update to version 4.5.4.1991 build 20220329, 5.0.0.1986 build
  20220324 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-13");

  exit(0);

}

include("host_details.inc");
include("version_func.inc");

if ( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX ) )
  exit(0);

CPE = infos["cpe"];

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit(0);

if ( version_is_less( version:version, test_version:"4.5.4_20220329" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.5.4_20220329" );
  security_message( port:0, data:report );
  exit(0);
}

if ( version_in_range_exclusive( version:version, test_version_lo:"5.0.0", test_version_up:"5.0.0_20220324" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.0_20220324" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
