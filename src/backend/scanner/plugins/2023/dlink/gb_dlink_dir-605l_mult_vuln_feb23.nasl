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

CPE = "cpe:/o:d-link:dir-605l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170313");
  script_version("2023-02-22T10:10:00+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:10:00 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-21 18:07:42 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2023-24343", "CVE-2023-24344", "CVE-2023-24345", "CVE-2023-24346",
                "CVE-2023-24347", "CVE-2023-24348", "CVE-2023-24349", "CVE-2023-24350",
                "CVE-2023-24351", "CVE-2023-24352");

  script_name("D-Link DIR-605L <= 2.13B01 Multiple Stack Overflow Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-605L revision B devices are prone to multiple stack
  overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-24343: stack overflow via the curTime parameter at /goform/formSchedule.

  - CVE-2023-24344: stack overflow via the webpage parameter at /goform/formWlanGuestSetup.

  - CVE-2023-24345: stack overflow via the curTime parameter at /goform/formSetWanDhcpplus.

  - CVE-2023-24346: stack overflow via the wan_connected parameter at /goform/formEasySetupWizard3.

  - CVE-2023-24347: stack overflow via the webpage parameter at /goform/formSetWanDhcpplus.

  - CVE-2023-24348: stack overflow via the curTime parameter at /goform/formSetACLFilter.

  - CVE-2023-24349: stack overflow via the curTime parameter at /goform/formSetRoute.

  - CVE-2023-24350: stack overflow via the config.smtp_email_subject parameter at
  /goform/formSetEmail.

  - CVE-2023-24351: stack overflow via the FILECODE parameter at /goform/formLogin.

  - CVE-2023-24352: stack overflow via the webpage parameter at /goform/formWPS.");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev B through firmware version 2.13B01.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for DIR-605L has ended in 24.09.2019, therefore
  most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://support.dlink.com/ProductInfo.aspx?m=DIR-605L");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/03");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/04");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/03");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/03");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
security_message( port:port, data:report );
exit( 0 );
