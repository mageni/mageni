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
  script_oid("1.3.6.1.4.1.25623.1.0.170304");
  script_version("2023-02-21T10:09:30+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-04 21:45:34 +0000 (Sat, 04 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-13263", "CVE-2019-13264", "CVE-2019-13265");

  script_name("D-Link DIR-825 Rev G1 <= 1.04Beta, DIR-882 Rev A1 <= 1.30b06Beta Multiple Router Isolation Bypass Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-825 and DIR-882 devices are prone to multiple router
  isolation bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following router isolation bypass vulnerabilities exist:

  - CVE-2019-13263: DHCP attack

  - CVE-2019-13264: IGMP attack

  - CVE-2019-13265: ARP attack");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev G1 prior to firmware version 2.06b01
  and DIR-882 Rev A1 prior to 1.30b06Beta.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10121");
  script_xref(name:"URL", value:"https://www.usenix.org/system/files/woot19-paper_ovadia.pdf");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:d-link:dir-825_firmware",
                      "cpe:/o:d-link:dir-882_firmware" );

if ( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if ( ! version = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

hw_version = get_kb_item( "d-link/dir/hw_version" );
if ( ! hw_version )
  exit( 0 );

#nb: The advisory makes reference to "All HW Rev Gx"
if ( cpe == "cpe:/o:d-link:dir-825_firmware" ) {
  if ( hw_version =~ "G" && ( revcomp( a:version, b:"1.04Beta" ) < 0 ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.04Beta", extra:"Hardware revision: " + hw_version );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if ( cpe == "cpe:/o:d-link:dir-882_firmware" ) {
  if ( hw_version =~ "A" && ( revcomp( a:version, b:"1.30b06Beta" ) < 0 ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.30b06Beta", extra:"Hardware revision: " + hw_version );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
