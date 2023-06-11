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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3446");
  script_cve_id("CVE-2023-0386", "CVE-2023-31436", "CVE-2023-32233");
  script_tag(name:"creation_date", value:"2023-06-07 04:20:59 +0000 (Wed, 07 Jun 2023)");
  script_version("2023-06-08T05:05:11+0000");
  script_tag(name:"last_modification", value:"2023-06-08 05:05:11 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-15 21:15:00 +0000 (Mon, 15 May 2023)");

  script_name("Debian: Security Advisory (DLA-3446)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3446");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3446");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-5.10");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-5.10' package(s) announced via the DLA-3446 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2023-0386

It was discovered that under certain conditions the overlayfs filesystem implementation did not properly handle copy up operations. A local user permitted to mount overlay mounts in user namespaces can take advantage of this flaw for local privilege escalation.

CVE-2023-31436

Gwangun Jung reported a a flaw causing heap out-of-bounds read/write errors in the traffic control subsystem for the Quick Fair Queueing scheduler (QFQ) which may result in information leak, denial of service or privilege escalation.

CVE-2023-32233

Patryk Sondej and Piotr Krysiuk discovered a use-after-free flaw in the Netfilter nf_tables implementation when processing batch requests, which may result in local privilege escalation for a user with the CAP_NET_ADMIN capability in any user or network namespace.

For Debian 10 buster, these problems have been fixed in version 5.10.179-1~deb10u1.

We recommend that you upgrade your linux-5.10 packages.

For the detailed security status of linux-5.10 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp-lpae", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-rt-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-686-pae", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-686", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-amd64", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-arm64", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-armmp-lpae", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-cloud-amd64", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-cloud-arm64", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-common-rt", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-common", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-rt-686-pae", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-rt-amd64", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-rt-arm64", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-rt-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-pae-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-signed-template", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-signed-template", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-amd64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-arm64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-i386-signed-template", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-686-pae-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-amd64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-arm64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-686-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-686-pae-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-686-pae-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-686-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-amd64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-amd64-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-arm64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-arm64-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-armmp-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-armmp-lpae-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-armmp-lpae", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-cloud-amd64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-cloud-amd64-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-cloud-arm64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-cloud-arm64-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-686-pae-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-686-pae-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-amd64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-amd64-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-arm64-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-arm64-unsigned", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-armmp-dbg", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.23-rt-armmp", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.23", ver:"5.10.179-1~deb10u1", rls:"DEB10"))) {
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
