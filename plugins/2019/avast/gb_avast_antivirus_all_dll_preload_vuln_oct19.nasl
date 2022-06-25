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

CPE = "cpe:/a:avast:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107737");
  script_version("2019-10-29T06:41:59+0000");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-10-29 06:41:59 +0000 (Tue, 29 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-26 18:39:30 +0200 (Sat, 26 Oct 2019)");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-17093");

  script_name("Avast Antivirus (All Editions) < 19.8 DLL Preloading Vulnerability (Windows)");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("avast/antivirus/detected");

  script_tag(name:"summary", value:"This host is running Avast Antivirus and is prone to
  a dll preloading vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability gives attackers the ability to:

  - load and execute malicious payloads using multiple signed services, within the context of Avast
  signed processes

  - bypass the part of the self-defense mechanism that should prevent an attacker from tampering with processes
  and files of Avast Antivirus and load an arbitrary DLL into the Antivirus process

  - load and execute malicious payloads in a persistent way, each time the services are loaded.");

  script_tag(name:"impact", value:"The vulnerability can be used to achieve self-defense bypass, defense evasion,
  persistence and privilege escalation.");

  script_tag(name:"affected", value:"All Editions of Avast Antivirus before version 19.8.");

  script_tag(name:"solution", value:"Update to Avast Antivirus version 19.8 or later.");

  script_xref(name:"URL", value:"https://safebreach.com/Post/Avast-Antivirus-AVG-Antivirus-DLL-Preloading-into-PPL-and-Potential-Abuses");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"19.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"19.8", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
