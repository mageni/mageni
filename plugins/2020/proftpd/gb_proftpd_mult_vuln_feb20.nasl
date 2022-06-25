# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113645");
  script_version("2020-02-25T10:11:08+0000");
  script_tag(name:"last_modification", value:"2020-02-25 11:00:29 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-21 11:37:46 +0000 (Fri, 21 Feb 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-9272", "CVE-2020-9273");

  script_name("ProFTPD < 1.3.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_mandatory_keys("ProFTPD/Installed");

  script_tag(name:"summary", value:"ProFTPD is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - There is an out-of-bounds (OOB) read vulnerability in mod_cap
    via the cap_text.c cap_to_text function.

  - It is possible to corrupt the memory pool by interrupting the data transfer channel.
    This triggers a use-after-free in alloc_pool in pool.c.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read sensitive information
  or execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"ProFTPD through version 1.3.6.");

  script_tag(name:"solution", value:"Update to version 1.3.7.");

  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/902");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/903");

  exit(0);
}

CPE = "cpe:/a:proftpd:proftpd";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull (port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
