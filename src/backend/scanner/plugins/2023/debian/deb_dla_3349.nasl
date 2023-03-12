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
  script_oid("1.3.6.1.4.1.25623.1.0.893349");
  script_cve_id("CVE-2022-2873", "CVE-2022-3545", "CVE-2022-3623", "CVE-2022-36280", "CVE-2022-41218", "CVE-2022-45934", "CVE-2022-4696", "CVE-2022-47929", "CVE-2023-0179", "CVE-2023-0240", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-23586");
  script_tag(name:"creation_date", value:"2023-03-03 02:00:16 +0000 (Fri, 03 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:00 +0000 (Mon, 06 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-3349)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3349");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3349");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-5.10");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-5.10' package(s) announced via the DLA-3349 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2022-2873

Zheyu Ma discovered that an out-of-bounds memory access flaw in the Intel iSMT SMBus 2.0 host controller driver may result in denial of service (system crash).

CVE-2022-3545

It was discovered that the Netronome Flow Processor (NFP) driver contained a use-after-free flaw in area_cache_get(), which may result in denial of service or the execution of arbitrary code.

CVE-2022-3623

A race condition when looking up a CONT-PTE/PMD size hugetlb page may result in denial of service or an information leak.

CVE-2022-4696

A use-after-free vulnerability was discovered in the io_uring subsystem.

CVE-2022-36280

An out-of-bounds memory write vulnerability was discovered in the vmwgfx driver, which may allow a local unprivileged user to cause a denial of service (system crash).

CVE-2022-41218

Hyunwoo Kim reported a use-after-free flaw in the Media DVB core subsystem caused by refcount races, which may allow a local user to cause a denial of service or escalate privileges.

CVE-2022-45934

An integer overflow in l2cap_config_req() in the Bluetooth subsystem was discovered, which may allow a physically proximate attacker to cause a denial of service (system crash).

CVE-2022-47929

Frederick Lawler reported a NULL pointer dereference in the traffic control subsystem allowing an unprivileged user to cause a denial of service by setting up a specially crafted traffic control configuration.

CVE-2023-0179

Davide Ornaghi discovered incorrect arithmetic when fetching VLAN header bits in the netfilter subsystem, allowing a local user to leak stack and heap addresses or potentially local privilege escalation to root.

CVE-2023-0240

A flaw was discovered in the io_uring subsystem that could lead to a use-after-free. A local user could exploit this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2023-0266

A use-after-free flaw in the sound subsystem due to missing locking may result in denial of service or privilege escalation.

CVE-2023-0394

Kyle Zeng discovered a NULL pointer dereference flaw in rawv6_push_pending_frames() in the network subsystem allowing a local user to cause a denial of service (system crash).

CVE-2023-23454

Kyle Zeng reported that the Class Based Queueing (CBQ) network scheduler was prone to denial of service due to interpreting classification results before checking the classification return code.

CVE-2023-23455

Kyle Zeng reported that the ATM Virtual Circuits (ATM) network scheduler was prone to a denial of service due to interpreting classification results before checking the classification return code.

CVE-2023-23586

A flaw was discovered in the io_uring subsystem that could lead to an information leak. A local user could exploit this to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-5.10' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp-lpae", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-rt-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-686-pae", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-686", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-amd64", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-arm64", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-armmp-lpae", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-cloud-amd64", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-cloud-arm64", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-common-rt", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-common", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-rt-686-pae", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-rt-amd64", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-rt-arm64", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.21-rt-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-pae-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-signed-template", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-signed-template", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-amd64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-arm64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-i386-signed-template", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-686-pae-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-amd64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-arm64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-686-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-686-pae-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-686-pae-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-686-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-amd64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-amd64-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-arm64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-arm64-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-armmp-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-armmp-lpae-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-armmp-lpae", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-cloud-amd64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-cloud-amd64-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-cloud-arm64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-cloud-arm64-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-686-pae-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-686-pae-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-amd64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-amd64-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-arm64-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-arm64-unsigned", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-armmp-dbg", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.21-rt-armmp", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.21", ver:"5.10.162-1~deb10u1", rls:"DEB10"))) {
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
