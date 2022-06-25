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

CPE = "cpe:/a:putty:putty";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118083");
  script_version("2021-06-01T06:37:42+0000");
  script_tag(name:"last_modification", value:"2021-06-02 10:30:49 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-26 17:10:14 +0200 (Wed, 26 May 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-33500");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PuTTY < 0.75 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/detected");

  script_tag(name:"summary", value:"PuTTY is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"Remote servers are allowed to cause a denial of service
  (Windows GUI hang) by telling the PuTTY window to change its title repeatedly at high speed,
  which results in many SetWindowTextA or SetWindowTextW calls.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PuTTY before version 0.75.");

  script_tag(name:"solution", value:"Update to version 0.75 or later.");

  script_xref(name:"URL", value:"https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"0.75" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"0.75", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
