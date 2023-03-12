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

CPE = "cpe:/o:axis:207w_firmware";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170347");
  script_version("2023-03-07T10:09:08+0000");
  script_tag(name:"last_modification", value:"2023-03-07 10:09:08 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-07 09:02:07 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2023-22984");

  script_name("AXIS 207W Network Camera XSS Vulnerability (Feb 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"AXIS 207W network camera devices are prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a reflected XSS vulnerability in the web administration
  portal, which allows an attacker to execute arbitrary JavaScript via URL.");

  script_tag(name:"affected", value:"AXIS 207W Network Camera devices, all versions");

  script_tag(name:"solution", value:"No known solution is available as of 07th March, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://d0ub1e-d.github.io/2022/12/30/exploit-db-1/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version: version, fixed_version: "None" );
security_message( data: report, port: 0 );
exit( 0 );

