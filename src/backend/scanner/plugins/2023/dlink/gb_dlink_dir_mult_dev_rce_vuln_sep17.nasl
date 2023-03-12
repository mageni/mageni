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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170322");
  script_version("2023-02-28T10:08:51+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:08:51 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-24 21:18:49 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-05 13:48:00 +0000 (Thu, 05 Oct 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-1187");

  script_name("D-Link Multiple DIR Devices RCE Vulnerability (Sep 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"Multiple D-Link DIR devices are prone to a remote command
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The ping tool in multiple D-Link and TRENDnet devices allow remote
  attackers to execute arbitrary code via the ping_addr parameter to ping.ccp.");

  script_tag(name:"affected", value:"D-Link DIR-626L, DIR-636L, DIR-808L, DIR-810L, DIR-820L,
  DIR-826L, DIR-830L and DIR-836L devices.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: CISA states that the impacted devices are end-of-life and should be disconnected if still
  in use.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/131465/D-Link-TRENDnet-NCC-Service-Command-Injection.html");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/130607/D-Link-DIR636L-Remote-Command-Injection.html");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2015/Mar/15");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:d-link:dir-626l_firmware",
                      "cpe:/o:d-link:dir-636l_firmware",
                      "cpe:/o:d-link:dir-808l_firmware",
                      "cpe:/o:d-link:dir-810l_firmware",
                      "cpe:/o:d-link:dir-820l_firmware",
                      "cpe:/o:d-link:dir-826l_firmware",
                      "cpe:/o:d-link:dir-830l_firmware",
                      "cpe:/o:d-link:dir-836l_firmware" );

if ( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if ( ! version = get_app_version( cpe:cpe, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:port, data:report );
exit( 0 );
