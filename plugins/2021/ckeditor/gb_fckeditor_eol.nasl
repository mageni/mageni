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

CPE = "cpe:/a:fckeditor:fckeditor";

if(description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.117499");
  script_version("2021-06-16T12:35:15+0000");
  script_tag(name:"last_modification", value:"2021-06-17 10:43:15 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-16 12:20:23 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FCKeditor End of Life (EOL) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_fckeditor_http_detect.nasl");
  script_mandatory_keys("fckeditor/detected");

  script_tag(name:"summary", value:"The remote host is using the FCKeditor which is discontinued and
  will not receive any security updates.");

  script_tag(name:"vuldetect", value:"Checks if the target host is using a discontinued product.");

  script_tag(name:"impact", value:"A discontinued product is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the
  security of this host.");

  script_tag(name:"solution", value:"Replace FCKeditor with CKEditor which is still supported by the
  vendor.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! loc = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

report = build_eol_message( name:"FCKeditor",
                            cpe:CPE,
                            location:loc,
                            skip_version:TRUE,
                            eol_version:"All versions",
                            eol_date:"unknown",
                            eol_type:"prod" );
security_message( port:port, data:report );
exit( 0 );