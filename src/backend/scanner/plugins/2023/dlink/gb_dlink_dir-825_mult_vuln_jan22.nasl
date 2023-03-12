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

CPE = "cpe:/o:d-link:dir-825_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170307");
  script_version("2023-02-21T10:09:30+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-14 18:44:22 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 13:28:00 +0000 (Fri, 06 May 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-46441", "CVE-2021-46442");

  script_name("D-Link DIR-825 Rev Gx <= 7.12B01_Beta Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-825 revision Gx devices are prone to multiple router
  isolation bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist in the 'webupg' binary:

  - CVE-2021-46441: Because of the lack of parameter verification, attackers can use 'cmd' parameters
  to execute arbitrary system commands after obtaining authorization.

  - CVE-2021-46442: Attackers can bypass authentication through parameters 'autoupgrade.asp', and
  perform functions such as downloading configuration files and updating firmware without
  authorization.");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev Gx prior to firmware version 7.12B01_Beta.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10294");
  script_xref(name:"URL", value:"https://github.com/tgp-top/D-Link-DIR-825");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

hw_version = get_kb_item( "d-link/dir/hw_version" );
if ( ! hw_version )
  exit( 0 );

if ( hw_version =~ "G" && ( revcomp( a:version, b:"7.12B01_Beta" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.12B01_Beta", install_path:location, extra:"Hardware revision: " + hw_version );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
