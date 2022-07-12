# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.892114");
  script_version("2020-03-03T04:00:55+0000");
  script_cve_id("CVE-2018-13093", "CVE-2018-13094", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-0136", "CVE-2019-10220", "CVE-2019-14615", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-15098", "CVE-2019-15217", "CVE-2019-15291", "CVE-2019-15505", "CVE-2019-15917", "CVE-2019-16746", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-18282", "CVE-2019-18683", "CVE-2019-18809", "CVE-2019-19037", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19447", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19767", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-2215");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-03 11:02:28 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-03 04:00:55 +0000 (Tue, 03 Mar 2020)");
  script_name("Debian LTS: Security Advisory for linux-4.9 (DLA-2114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00001.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2114-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/869511");
  script_xref(name:"URL", value:"https://bugs.debian.org/945023");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-4.9'
  package(s) announced via the DLA-2114-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2018-13093, CVE-2018-13094

Wen Xu from SSLab at Gatech reported several NULL pointer
dereference flaws that may be triggered when mounting and
operating a crafted XFS volume. An attacker able to mount
arbitrary XFS volumes could use this to cause a denial of service
(crash).

CVE-2018-20976

It was discovered that the XFS file-system implementation did not
correctly handle some mount failure conditions, which could lead
to a use-after-free. The security impact of this is unclear.

CVE-2018-21008

It was discovered that the rsi wifi driver did not correctly
handle some failure conditions, which could lead to a use-after-
free. The security impact of this is unclear.

CVE-2019-0136

It was discovered that the wifi soft-MAC implementation (mac80211)
did not properly authenticate Tunneled Direct Link Setup (TDLS)
messages. A nearby attacker could use this for denial of service
(loss of wifi connectivity).

CVE-2019-2215

The syzkaller tool discovered a use-after-free vulnerability in
the Android binder driver. A local user on a system with this
driver enabled could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.
However, this driver is not enabled on Debian packaged kernels.

CVE-2019-10220

Various developers and researchers found that if a crafted file-
system or malicious file server presented a directory with
filenames including a '/' character, this could confuse and
possibly defeat security checks in applications that read the
directory.

The kernel will now return an error when reading such a directory,
rather than passing the invalid filenames on to user-space.

CVE-2019-14615

It was discovered that Intel 9th and 10th generation GPUs did not
clear user-visible state during a context switch, which resulted
in information leaks between GPU tasks. This has been mitigated
in the i915 driver.

The affected chips (gen9 and gen10) are listed at
<

CVE-2019-14814, CVE-2019-14815, CVE-2019-14816

Multiple bugs were discovered in the mwifiex wifi driver, which
could lead to heap buffer overflows. A local user permitted to
configure a device handled by this driver could probably use this
for privilege escalation.

CVE-2019-14895, CVE-2019-14901

ADLab of Venustech discovered potential heap buffer overflows in
the mwifiex wifi driver. On systems using this driver, a
malicious Wireless Access Point or adhoc/P2P peer could use these
to cause a denial of service (memory corruption or crash) or
possibly for remote code ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.9.210-1~deb8u1. This update additionally fixes Debian bugs
#869511 and 945023, and includes many more bug fixes from stable
updates 4.9.190-4.9.210 inclusive.

We recommend that you upgrade your linux-4.9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-686", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-armel", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-armhf", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-i386", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-armmp", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-armmp-lpae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-common", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-common-rt", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-marvell", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-rt-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-rt-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-686", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-armel", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-armhf", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-i386", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-armmp", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-armmp-lpae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-common", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-common-rt", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-marvell", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-rt-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-rt-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686-pae-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-amd64-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-armmp", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-armmp-lpae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-marvell", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-686-pae-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-amd64-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-686", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-686-pae-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-amd64-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-armmp", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-armmp-lpae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-marvell", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-686-pae", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-686-pae-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-amd64", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-amd64-dbg", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.11", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.12", ver:"4.9.210-1~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
