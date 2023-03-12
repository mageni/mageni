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

CPE = "cpe:/o:d-link:dir-867_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170328");
  script_version("2023-03-06T10:10:03+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:10:03 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-01 15:04:08 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2022-41140");

  script_name("D-Link DIR-867 Rev. A <= v1.30B07 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-867 Rev. A devices are prone to a remote command
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The specific flaw exists within the lighttpd service, which
  listens on TCP port 80 by default. The issue results from the lack of proper validation of the
  length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker
  can leverage this vulnerability to execute code in the context of root.");

  script_tag(name:"affected", value:"D-Link DIR-867 Rev. A devices through firmware version
  1.30B07.");

  script_tag(name:"solution", value:"No known solution is available as of 01st March, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://support.dlink.com/ProductInfo.aspx?m=DIR-867-US");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10291");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-1290/");
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

hw_version = get_kb_item( "d-link/dir/hw_version" );
if ( ! hw_version )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( ( hw_version =~ "A" ) && ( revcomp( a:version, b:"1.30B07" ) <= 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", extra:"Hardware revision: " + hw_version );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
