# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113727");
  script_version("2020-07-22T10:07:48+0000");
  script_tag(name:"last_modification", value:"2020-07-23 09:54:39 +0000 (Thu, 23 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-22 09:11:41 +0000 (Wed, 22 Jul 2020)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-13659", "CVE-2020-13754", "CVE-2020-13791", "CVE-2020-13800", "CVE-2020-15859");

  script_name("QEMU <= 4.2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_qemu_detect_lin.nasl");
  script_mandatory_keys("QEMU/Lin/Ver");

  script_tag(name:"summary", value:"QEMU is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - address_space_map in exec.c can trigger a NULL pointer dereference related to BounceBuffer. (CVE-2020-13659)

  - hw/pci/msix.c allows guest OS users to trigger an out-of-bounds access
    via a crafted address in an msi-x mmio operation. (CVE-2020-13754)

  - hw/pci/pci.c allows guest OS users to trigger an out-of-bounds access
    by providing an address near the end of the PCI configuration space. (CVE-2020-13791)

  - ati-vga in hw/display/ati.c allows guest OS users to trigger infinite recursion
    via a crafted mm_index value during an ati_mm_read or ati_mm_write call. (CVE-2020-13800)

  - There is a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e packet
    with the data's address set to the e1000e's MMIO address. (CVE-2020-15859)");

  script_tag(name:"affected", value:"QEMU through version 4.2.0.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/06/01/3");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/06/01/6");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/06/15/8");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/06/04/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/06/04/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/07/21/3");

  exit(0);
}

CPE = "cpe:/a:qemu:qemu";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.1", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
