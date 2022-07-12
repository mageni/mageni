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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0113");
  script_cve_id("CVE-2018-12207", "CVE-2019-11135", "CVE-2019-17349", "CVE-2019-17350", "CVE-2019-18420", "CVE-2019-18421", "CVE-2019-18422", "CVE-2019-18423", "CVE-2019-18424", "CVE-2019-18425");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-14 16:15:00 +0000 (Thu, 14 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0113)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0113");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0113.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25782");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-295.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-296.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-298.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-299.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-301.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-302.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-303.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-304.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-305.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-306.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the MGASA-2020-0113 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Updated from 4.12.0 to 4.12.1
- Device quarantine for alternate pci assignment methods [XSA-306]
- x86: Machine Check Error on Page Size Change DoS [XSA-304, CVE-2018-12207]
- TSX Asynchronous Abort speculative side channel [XSA-305, CVE-2019-11135]
- VCPUOP_initialise DoS [XSA-296, CVE-2019-18420] (rhbz#1771368)
- missing descriptor table limit checking in x86 PV emulation [XSA-298,
 CVE-2019-18425] (rhbz#1771341)
- Issues with restartable PV type change operations [XSA-299, CVE-2019-18421]
 (rhbz#1767726)
- add-to-physmap can be abused to DoS Arm hosts [XSA-301, CVE-2019-18423]
 (rhbz#1771345)
- passed through PCI devices may corrupt host memory after deassignment
 [XSA-302, CVE-2019-18424] (rhbz#1767731)
- ARM: Interrupts are unconditionally unmasked in exception handlers
 [XSA-303, CVE-2019-18422] (rhbz#1771443)
- Unlimited Arm Atomics Operations [XSA-295, CVE-2019-17349,
 CVE-2019-17350] (rhbz#1720760)
- fix HVM DomU boot on some chipsets
- adjust grub2 workaround");

  script_tag(name:"affected", value:"'xen' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64xen-devel", rpm:"lib64xen-devel~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xen3.0", rpm:"lib64xen3.0~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen-devel", rpm:"libxen-devel~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen3.0", rpm:"libxen3.0~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen", rpm:"ocaml-xen~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen-devel", rpm:"ocaml-xen-devel~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc", rpm:"xen-doc~4.12.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-hypervisor", rpm:"xen-hypervisor~4.12.1~1.mga7", rls:"MAGEIA7"))) {
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
