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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118173");
  script_version("2021-08-25T14:53:51+0000");
  script_cve_id("CVE-2021-34407");  # Disputed by NVD but used by references
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-25 14:53:51 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-25 16:08:43 +0200 (Wed, 25 Aug 2021)");
  script_name("Zoom Client Heap Based Buffer Overflow - Aug21");

  script_tag(name:"summary", value:"Zoom Client is prone to a heap based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows remote attackers to execute arbitrary
  code on affected installations of Zoom Clients. Authentication is not required to exploit this
  vulnerability.

  The specific flaw exists within the processing of encrypted messages. The issue results from the lack
  of proper validation of the length of user-supplied data prior to copying it to a fixed-length
  heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the
  current user.");

  script_tag(name:"affected", value:"All desktop versions of the Zoom Client for Meetings before 5.6.3.");

  script_tag(name:"solution", value:"Update to version 5.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_detect_macosx.nasl", "gb_zoom_client_detect_win.nasl");
  script_mandatory_keys("zoom/client/detected");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-21-971");
  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"5.6.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.6.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
