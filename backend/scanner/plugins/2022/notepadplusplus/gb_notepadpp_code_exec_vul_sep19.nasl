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

CPE = "cpe:/a:notepad-plus-plus:notepad++";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821281");
  script_version("2022-08-03T09:00:48+0000");
  script_cve_id("CVE-2019-16294");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-03 09:00:48 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2022-08-02 11:37:23 +0000 (Tue, 02 Aug 2022)");
  script_name("Notepad++ < 7.7 RCE Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_notepadpp_detect_portable_win.nasl");
  script_mandatory_keys("Notepad++64/Win/installed");

  script_xref(name:"URL", value:"https://github.com/bi7s/CVEs/tree/master/CVE-2019-16294");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/154706");

  script_tag(name:"summary", value:"Notepad++ is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a memory corruption in Notepad++ in the
  Scintilla component.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct denial of
  service attack or potentially allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"Notepad++ versions prior to 7.7.");

  script_tag(name:"solution", value:"Update to version 7.7 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"7.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.7", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
