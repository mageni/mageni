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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117197");
  script_version("2021-02-08T13:28:09+0000");
  script_tag(name:"last_modification", value:"2021-02-09 11:23:12 +0000 (Tue, 09 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-08 11:41:10 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Adobe Flash Player End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl", "gb_adobe_flash_player_detect_win.nasl",
                      "gb_adobe_flash_player_plugin_detect_win.nasl", "gb_flash_player_within_google_chrome_detect_lin.nasl",
                      "gb_flash_player_within_google_chrome_detect_macosx.nasl", "gb_flash_player_within_google_chrome_detect_win.nasl",
                      "gb_flash_player_within_ie_edge_detect.nasl", "secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("adobe/flash_player/detected");

  script_xref(name:"URL", value:"https://www.adobe.com/products/flashplayer/end-of-life.html");
  script_xref(name:"URL", value:"https://theblog.adobe.com/adobe-flash-update/");

  script_tag(name:"summary", value:"The Adobe Flash Player on the remote host has reached the End of Life (EOL)
  / is discontinued and should not be used anymore.");

  script_tag(name:"impact", value:"An EOL / discontinued product is not receiving any security updates from the
  vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.

  Note: The product has reached its EOL.");

  script_tag(name:"vuldetect", value:"Checks if the target host is using an EOL / discontinued product.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

cpe_list = make_list( "cpe:/a:adobe:flash_player",
                      "cpe:/a:adobe:flash_player_internet_explorer",
                      "cpe:/a:adobe:flash_player_edge",
                      "cpe:/a:adobe:flash_player_chrome" );

if( ! infos = get_app_location_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
loc = infos["location"];

report = build_eol_message( name:"Adobe Flash Player",
                            cpe:cpe,
                            location:loc,
                            eol_date:"2020-12-31",
                            eol_url:"https://www.adobe.com/products/flashplayer/end-of-life.html",
                            eol_type:"prod",
                            skip_version:TRUE );
security_message( port:0, data:report );

exit( 0 );
