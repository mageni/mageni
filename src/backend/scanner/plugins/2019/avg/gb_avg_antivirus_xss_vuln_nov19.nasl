# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:avg:anti-virus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107745");
  script_version("2019-11-09T19:25:32+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-11-09 19:25:32 +0000 (Sat, 09 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-09 19:15:34 +0100 (Sat, 09 Nov 2019)");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-18654");

  script_name("AVG Antivirus <= 19.3.3084 XSS Vulnerability (Windows)");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_avg_detect_win.nasl");
  script_mandatory_keys("avg/antivirus/detected");

  script_tag(name:"summary", value:"This host is running AVG Antivirus and is prone to
  a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A Cross Site Scripting (XSS) issue exists in AVG AntiVirus.");

  script_tag(name:"impact", value:"The vulnerability allows an attacker to execute JavaScript code via an SSID Name
  in a Network Notification Popup.");

  script_tag(name:"affected", value:"AVG Antivirus before version 19.4.");

  script_tag(name:"solution", value:"Update to AVG Antivirus version 19.4 or later.");

  script_xref(name:"URL", value:"https://medium.com/@YoKoKho/5-000-usd-xss-issue-at-avast-desktop-antivirus-for-windows-yes-desktop-1e99375f0968");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"19.3.3084" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"19.4", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
