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
  script_oid("1.3.6.1.4.1.25623.1.0.113766");
  script_version("2020-09-30T09:30:12+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-30 08:50:29 +0000 (Wed, 30 Sep 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("rlogin Passwordless Login");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_rlogin_detect.nasl");
  script_mandatory_keys("rlogin/detected", "rlogin/nopass");

  script_tag(name:"summary", value:"The rlogin service allows root access without a password.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability allows an attacker to gain
  complete control over the target system.");

  script_tag(name:"solution", value:"Disable the rlogin service and use alternatives like SSH instead.");

  exit(0);
}

include( "host_details.inc" );

if( ! get_kb_item( "rlogin/nopass" ) ) exit( 0 );
if( ! port = get_kb_item( "rlogin/port" ) ) exit( 0 );

report = "It was possible to gain root access without a password.";
security_message( data: report, port: port );

exit( 0 );
