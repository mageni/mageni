# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113381");
  script_version("2019-05-06T13:46:04+0000");
  script_tag(name:"last_modification", value:"2019-05-06 13:46:04 +0000 (Mon, 06 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-02 12:52:59 +0000 (Thu, 02 May 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5008");
  script_bugtraq_id(108024);

  script_name("QEMU <= 3.1.50 Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_qemu_detect_lin.nasl");
  script_mandatory_keys("QEMU/Lin/Ver");

  script_tag(name:"summary", value:"QEMU is prone to a Denial of Service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"hw/sparc64/sun4u.c is vulnerable to a NULL pointer dereference, which allows
  an attacker to cause a denial of service via a device driver.");
  script_tag(name:"affected", value:"QEMU through version 3.1.50.");
  script_tag(name:"solution", value:"Update to version 4.0.0.");

  script_xref(name:"URL", value:"https://fakhrizulkifli.github.io/posts/2019/01/03/CVE-2019-5008/");
  script_xref(name:"URL", value:"https://git.qemu.org/?p=qemu.git;a=history;f=hw/sparc64/sun4u.c;hb=HEAD");

  exit(0);
}

CPE = "cpe:/a:qemu:qemu";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
location = infos["location"];
version = infos["version"];

if( version_is_less( version: version, test_version: "4.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
