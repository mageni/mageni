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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3362");
  script_cve_id("CVE-2020-14394", "CVE-2020-17380", "CVE-2020-29130", "CVE-2021-3409", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595", "CVE-2022-0216", "CVE-2022-1050");
  script_tag(name:"creation_date", value:"2023-03-15 04:23:07 +0000 (Wed, 15 Mar 2023)");
  script_version("2023-03-15T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-03-15 10:08:41 +0000 (Wed, 15 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 12:26:00 +0000 (Fri, 08 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-3362)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3362");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3362");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/qemu");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-3362 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in QEMU, a fast processor emulator, which could result in denial of service, information leak, or potentially the execution of arbitrary code.

CVE-2020-14394

An infinite loop flaw was found in the USB xHCI controller emulation of QEMU while computing the length of the Transfer Request Block (TRB) Ring. This flaw allows a privileged guest user to hang the QEMU process on the host, resulting in a denial of service.

CVE-2020-17380/CVE-2021-3409 A heap-based buffer overflow was found in QEMU in the SDHCI device emulation support. It could occur while doing a multi block SDMA transfer via the sdhci_sdma_transfer_multi_blocks() routine in hw/sd/sdhci.c. A guest user or process could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition, or potentially execute arbitrary code with privileges of the QEMU process on the host.

CVE-2020-29130

slirp.c has a buffer over-read because it tries to read a certain amount of header data even if that exceeds the total packet length.

CVE-2021-3592

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the bootp_input() function and could occur while processing a udp packet that is smaller than the size of the bootp_t structure. A malicious guest could use this flaw to leak 10 bytes of uninitialized heap memory from the host.

CVE-2021-3593

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the size of the udphdr structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest.

CVE-2021-3594

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the udp_input() function and could occur while processing a udp packet that is smaller than the size of the udphdr structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest.

CVE-2021-3595

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the size of the tftp_t structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest.

CVE-2022-0216

A use-after-free vulnerability was found in the LSI53C895A SCSI Host Bus Adapter emulation of QEMU. The flaw occurs while processing repeated messages to cancel the current SCSI request via the lsi_do_msgout function. This flaw allows a malicious privileged user within the guest to crash the QEMU process on the host, resulting in a denial of service.

CVE-2022-1050

A flaw was found in the QEMU ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu-block-extra", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-data", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-gui", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:3.1+dfsg-8+deb10u10", rls:"DEB10"))) {
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
