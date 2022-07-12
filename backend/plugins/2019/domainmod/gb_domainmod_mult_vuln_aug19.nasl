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
  script_oid("1.3.6.1.4.1.25623.1.0.113491");
  script_version("2020-05-11T13:45:27+0000");
  script_tag(name:"last_modification", value:"2020-05-12 09:56:07 +0000 (Tue, 12 May 2020)");
  script_tag(name:"creation_date", value:"2019-09-03 11:55:23 +0000 (Tue, 03 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15811", "CVE-2020-12735");

  script_name("DomainMOD <= 4.13.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_domainmod_http_detect.nasl");
  script_mandatory_keys("domainmod/detected");

  script_tag(name:"summary", value:"DomainMOD is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A cross-site scripting (XSS) exists in the file reporting/domains/cost-by-month.php
  via the parameter daterange. (CVE-2019-15811)

  - There is insufficient entropy for password reset requests. (CVE-2020-12735)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site or take over the account of
  an existing user.");

  script_tag(name:"affected", value:"DomainMOD through version 4.13.0.");

  script_tag(name:"solution", value:"Update to version 4.14.0 or later.");

  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/108");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/122");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/154270/DomainMod-4.13-Cross-Site-Scripting.html");

  exit(0);
}

CPE = "cpe:/a:domainmod:domainmod";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.13.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.14.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
