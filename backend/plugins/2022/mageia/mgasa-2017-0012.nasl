# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0012");
  script_cve_id("CVE-2014-3672", "CVE-2016-10013", "CVE-2016-10024", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4480", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5242", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6259", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094", "CVE-2016-7777", "CVE-2016-9377", "CVE-2016-9378", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9381", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9384", "CVE-2016-9385", "CVE-2016-9386", "CVE-2016-9637", "CVE-2016-9932");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-14 15:43:00 +0000 (Thu, 14 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2017-0012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0012");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0012.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19901");
  script_xref(name:"URL", value:"https://www.xenproject.org/downloads/xen-archives/xen-45-series/xen-453.html");
  script_xref(name:"URL", value:"https://www.xenproject.org/downloads/xen-archives/xen-45-series/xen-455.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-172.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-173.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-175.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-176.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-178.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-179.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-180.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-181.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-182.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-183.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-184.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-185.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-186.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-187.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-190.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-191.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-192.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-193.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-194.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-195.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-196.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-197.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-198.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-199.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-200.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-202.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-204.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the MGASA-2017-0012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This xen update is based on upstream 4.5.5 maintenance release, and fixes
the following security issues:

The qemu implementation in libvirt before 1.3.0 and Xen allows local guest
OS users to cause a denial of service (host disk consumption) by writing
to stdout or stderr (CVE-2014-3672)

The xrstor function in arch/x86/xstate.c in Xen 4.x does not properly handle
writes to the hardware FSW.ES bit when running on AMD64 processors, which
allows local guest OS users to obtain sensitive register content information
from another guest by leveraging pending exception and mask bits. NOTE: this
vulnerability exists because of an incorrect fix for CVE-2013-2076
(CVE-2016-3158).

The fpu_fxrstor function in arch/x86/i387.c in Xen 4.x does not properly
handle writes to the hardware FSW.ES bit when running on AMD64 processors,
which allows local guest OS users to obtain sensitive register content
information from another guest by leveraging pending exception and mask
bits. NOTE: this vulnerability exists because of an incorrect fix for
CVE-2013-2076 (CVE-2016-3159).

The VGA module in QEMU improperly performs bounds checking on banked access
to video memory, which allows local guest OS administrators to execute
arbitrary code on the host by changing access modes after setting the bank
register, aka the 'Dark Portal' issue (CVE-2016-3710).

Integer overflow in the VGA module in QEMU allows local guest OS users to
cause a denial of service (out-of-bounds read and QEMU process crash) by
editing VGA registers in VBE mode (CVE-2016-3712).

Integer overflow in the x86 shadow pagetable code in Xen allows local guest
OS users to cause a denial of service (host crash) or possibly gain
privileges by shadowing a superpage mapping (CVE-2016-3960).

The libxl device-handling in Xen 4.6.x and earlier allows local OS guest
administrators to cause a denial of service (resource consumption or
management facility confusion) or gain host OS privileges by manipulating
information in guest controlled areas of xenstore (CVE-2016-4962).

The libxl device-handling in Xen through 4.6.x allows local guest OS users
with access to the driver domain to cause a denial of service (management
tool confusion) by manipulating information in the backend directories in
xenstore (CVE-2016-4963).

The guest_walk_tables function in arch/x86/mm/guest_walk.c in Xen 4.6.x and
earlier does not properly handle the Page Size (PS) page table entry bit at
the L4 and L3 page table levels, which might allow local guest OS users to
gain privileges via a crafted mapping of memory (CVE-2016-4480).

The p2m_teardown function in arch/arm/p2m.c in Xen 4.4.x through 4.6.x allows
local guest OS users with access to the driver domain to cause a denial of
service (NULL pointer dereference and host OS crash) by creating concurrent
domains and holding references to them, related to VMID exhaustion
(CVE-2016-5242).

The virtqueue_pop ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64xen-devel", rpm:"lib64xen-devel~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xen3.0", rpm:"lib64xen3.0~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen-devel", rpm:"libxen-devel~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen3.0", rpm:"libxen3.0~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen", rpm:"ocaml-xen~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen-devel", rpm:"ocaml-xen-devel~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc", rpm:"xen-doc~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-hypervisor", rpm:"xen-hypervisor~4.5.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
