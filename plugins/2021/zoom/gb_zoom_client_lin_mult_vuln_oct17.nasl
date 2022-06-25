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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117735");
  script_version("2021-10-19T13:03:13+0000");
  script_cve_id("CVE-2017-15048", "CVE-2017-15049");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-20 10:23:51 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-14 15:14:00 +0000 (Fri, 14 May 2021)");
  script_tag(name:"creation_date", value:"2021-10-19 10:32:29 +0000 (Tue, 19 Oct 2021)");
  script_name("Zoom Client < 2.0.115900.1201 Multiple Vulnerabilities (Oct 2017) - Linux");

  script_tag(name:"summary", value:"The Zoom Client is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-15048: Stack-based buffer overflow in the ZoomLauncher binary in the Zoom client for
  Linux allows remote attackers to execute arbitrary code by leveraging the zoommtg:// scheme
  handler.

  - CVE-2017-15049: The ZoomLauncher binary in the Zoom client for Linux does not properly sanitize
  user input when constructing a shell command, which allows remote attackers to execute arbitrary
  code by leveraging the zoommtg:// scheme handler.");

  script_tag(name:"affected", value:"Zoom Client versions prior to 2.0.115900.1201 on Linux.");

  script_tag(name:"solution", value:"Update to version 2.0.115900.1201 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/lin/detected");

  script_xref(name:"URL", value:"https://github.com/convisolabs/advisories/blob/master/2017/CONVISO-17-002.txt");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Dec/46");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43355/");
  script_xref(name:"URL", value:"https://github.com/convisolabs/advisories/blob/master/2017/CONVISO-17-003.txt");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Dec/47");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43354/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"2.0.115900.1201" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.115900.1201", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );