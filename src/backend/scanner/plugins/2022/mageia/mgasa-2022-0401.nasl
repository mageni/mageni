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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0401");
  script_cve_id("CVE-2022-0135", "CVE-2022-0175");
  script_tag(name:"creation_date", value:"2022-11-02 04:36:04 +0000 (Wed, 02 Nov 2022)");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 17:10:00 +0000 (Wed, 31 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0401)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0401");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0401.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29903");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-January/010013.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LNFLD35UGUIRPTGF3HA3JP2MXLLHWPIX/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-February/010243.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EQXVEUIFIMFD6G5N2JBQ2A6XUYVZBCSY/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5309-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virglrenderer' package(s) announced via the MGASA-2022-0401 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write issue was found in the VirGL virtual OpenGL
renderer (virglrenderer). This flaw allows a malicious guest to create a
specially crafted virgil resource and then issue a VIRTGPU_EXECBUFFER
ioctl, leading to a denial of service or possible code execution.
(CVE-2022-0135)

A flaw was found in the VirGL virtual OpenGL renderer (virglrenderer). The
virgl did not properly initialize memory when allocating a host-backed
memory resource. A malicious guest could use this flaw to mmap from the
guest kernel and read this uninitialized memory from the host, possibly
leading to information disclosure. (CVE-2022-0175)");

  script_tag(name:"affected", value:"'virglrenderer' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64virglrenderer-devel", rpm:"lib64virglrenderer-devel~0.8.2~1.20200212git7d204f39.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virglrenderer1", rpm:"lib64virglrenderer1~0.8.2~1.20200212git7d204f39.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirglrenderer-devel", rpm:"libvirglrenderer-devel~0.8.2~1.20200212git7d204f39.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirglrenderer1", rpm:"libvirglrenderer1~0.8.2~1.20200212git7d204f39.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virglrenderer", rpm:"virglrenderer~0.8.2~1.20200212git7d204f39.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virglrenderer-test-server", rpm:"virglrenderer-test-server~0.8.2~1.20200212git7d204f39.1.mga8", rls:"MAGEIA8"))) {
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
