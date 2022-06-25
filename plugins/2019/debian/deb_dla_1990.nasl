# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891990");
  script_version("2019-11-14T03:00:14+0000");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11091", "CVE-2019-11135");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-11-14 03:00:14 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-14 03:00:14 +0000 (Thu, 14 Nov 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1990-1] linux-4.9 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1990-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-4.9'
  package(s) announced via the DSA-1990-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service, or information
leak.

CVE-2018-12207

It was discovered that on Intel CPUs supporting hardware
virtualisation with Extended Page Tables (EPT), a guest VM may
manipulate the memory management hardware to cause a Machine Check
Error (MCE) and denial of service (hang or crash).

The guest triggers this error by changing page tables without a
TLB flush, so that both 4 KB and 2 MB entries for the same virtual
address are loaded into the instruction TLB (iTLB). This update
implements a mitigation in KVM that prevents guest VMs from
loading 2 MB entries into the iTLB. This will reduce performance
of guest VMs.

Further information on the mitigation can be found at
<

Intel's explanation of the issue can be found at
<

CVE-2019-0154

Intel discovered that on their 8th and 9th generation GPUs,
reading certain registers while the GPU is in a low-power state
can cause a system hang. A local user permitted to use the GPU
can use this for denial of service.

This update mitigates the issue through changes to the i915
driver.

The affected chips (gen8 and gen9) are listed at
<

CVE-2019-0155

Intel discovered that their 9th generation and newer GPUs are
missing a security check in the Blitter Command Streamer (BCS). A
local user permitted to use the GPU could use this to access any
memory that the GPU has access to, which could result in a denial
of service (memory corruption or crash), a leak of sensitive
information, or privilege escalation.

This update mitigates the issue by adding the security check to
the i915 driver.

The affected chips (gen9 onward) are listed at
<

CVE-2019-11135

It was discovered that on Intel CPUs supporting transactional
memory (TSX), a transaction that is going to be aborted may
continue to execute speculatively, reading sensitive data from
internal buffers and leaking it through dependent operations.
Intel calls this 'TSX Asynchronous Abort' (TAA).

For CPUs affected by the previously published Microarchitectural
Data Sampling (MDS) issues (CVE-2018-12126, CVE-2018-12127,
CVE-2018-12130, CVE-2019-11091), the existing mitigation also
mitigates this issue.

For processors that are vulnerable to TAA but not MDS, this update
disables TSX by default. This mitigation requires updated CPU
microcode. An updated intel-microcode package (only available in
Debian non-free) will be provided via a future DLA. The updated
CPU microcode may also be available as part of a system firmware
('BIOS') update.

Further information on the mitigation can be found at
<

Intel's explanation of the issue can be found at
<");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.9.189-3+deb9u2~deb8u1.

We recommend that you upgrade your linux-4.9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-686", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-686-pae", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-amd64", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-armel", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-armhf", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-i386", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-amd64", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-armmp", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-armmp-lpae", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-common", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-common-rt", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-marvell", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-rt-686-pae", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-rt-amd64", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686-pae", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686-pae-dbg", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-amd64", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-amd64-dbg", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-armmp", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-armmp-lpae", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-marvell", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-686-pae", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-686-pae-dbg", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-amd64", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-amd64-dbg", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.11", ver:"4.9.189-3+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);