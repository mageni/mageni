# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113690");
  script_version("2020-05-18T12:55:03+0000");
  script_tag(name:"last_modification", value:"2020-05-19 09:33:09 +0000 (Tue, 19 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-18 12:23:23 +0000 (Mon, 18 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2020-10813");

  script_name("FTPDMIN <= 0.96 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ftpdmin_detect.nasl");
  script_mandatory_keys("ftpdmin/installed");

  script_tag(name:"summary", value:"FTPMIN is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploitable via a crafted packet.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to crash the application.");

  script_tag(name:"affected", value:"FTPDMIN through version 0.96.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.povonsec.com/ftpdmin-denial-of-service-exploit/");

  exit(0);
}

CPE = "cpe:/a:ftpdmin:ftpdmin";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "0.96" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Will Not Fix", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
