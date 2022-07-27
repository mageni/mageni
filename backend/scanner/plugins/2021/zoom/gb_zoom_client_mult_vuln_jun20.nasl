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
  script_oid("1.3.6.1.4.1.25623.1.0.117736");
  script_version("2021-10-19T13:03:13+0000");
  script_cve_id("CVE-2020-6109", "CVE-2020-6110");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-20 10:23:51 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-11 20:34:00 +0000 (Thu, 11 Jun 2020)");
  script_tag(name:"creation_date", value:"2021-10-19 10:32:29 +0000 (Tue, 19 Oct 2021)");
  script_name("Zoom Client < 4.6.12 Multiple Vulnerabilities (Jun 2020)");

  script_tag(name:"summary", value:"The Zoom Client is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  CVE-2020-6109: Zoom client application chat Giphy arbitrary file write

  An exploitable path traversal vulnerability exists in the Zoom client while processing messages
  including animated GIFs. A specially crafted chat message can cause an arbitrary file write, which
  could potentially be abused to achieve arbitrary code execution. An attacker needs to send a
  specially crafted message to a target user or a group to exploit this vulnerability.

  CVE-2020-6110: Zoom Client Application Chat Code Snippet Remote Code Execution Vulnerability

  An exploitable partial path traversal vulnerability exists in the way Zoom Client processes
  messages including shared code snippets. A specially crafted chat message can cause an arbitrary
  binary planting which could be abused to achieve arbitrary code execution. An attacker needs to
  send a specially crafted message to a target user or a group to trigger this vulnerability. For
  the most severe effect, target user interaction is required.");

  script_tag(name:"affected", value:"Zoom Client versions prior to 4.6.12.");

  script_tag(name:"solution", value:"Update to version 4.6.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_ssh_login_macosx_detect.nasl", "gb_zoom_client_smb_login_detect.nasl",
                      "gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/detected");

  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2020/06/vuln-spotlight-zoom-code-execution-june-2020.html");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2020-1055");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2020-1056");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"4.6.12" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.6.12", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );