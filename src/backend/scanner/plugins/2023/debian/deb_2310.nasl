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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2310");
  script_cve_id("CVE-2009-4067", "CVE-2011-0712", "CVE-2011-1020", "CVE-2011-2208", "CVE-2011-2209", "CVE-2011-2211", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2525", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Debian: Security Advisory (DSA-2310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2310");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2310");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leak. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4067

Rafael Dominguez Vega of MWR InfoSecurity reported an issue in the auerswald module, a driver for Auerswald PBX/System Telephone USB devices. Attackers with physical access to a system's USB ports could obtain elevated privileges using a specially crafted USB device.

CVE-2011-0712

Rafael Dominguez Vega of MWR InfoSecurity reported an issue in the caiaq module, a USB driver for Native Instruments USB audio devices. Attackers with physical access to a system's USB ports could obtain elevated privileges using a specially crafted USB device.

CVE-2011-1020

Kees Cook discovered an issue in the /proc filesystem that allows local users to gain access to sensitive process information after execution of a setuid binary.

CVE-2011-2209

Dan Rosenberg discovered an issue in the osf_sysinfo() system call on the alpha architecture. Local users could obtain access to sensitive kernel memory.

CVE-2011-2211

Dan Rosenberg discovered an issue in the osf_wait4() system call on the alpha architecture permitting local users to gain elevated privileges.

CVE-2011-2213

Dan Rosenberg discovered an issue in the INET socket monitoring interface. Local users could cause a denial of service by injecting code and causing the kernel to execute an infinite loop.

CVE-2011-2484

Vasiliy Kulikov of Openwall discovered that the number of exit handlers that a process can register is not capped, resulting in local denial of service through resource exhaustion (CPU time and memory).

CVE-2011-2491

Vasily Averin discovered an issue with the NFS locking implementation. A malicious NFS server can cause a client to hang indefinitely in an unlock call.

CVE-2011-2492

Marek Kroemeke and Filip Palian discovered that uninitialized struct elements in the Bluetooth subsystem could lead to a leak of sensitive kernel memory through leaked stack memory.

CVE-2011-2495

Vasiliy Kulikov of Openwall discovered that the io file of a process' proc directory was world-readable, resulting in local information disclosure of information such as password lengths.

CVE-2011-2496

Robert Swiecki discovered that mremap() could be abused for local denial of service by triggering a BUG_ON assert.

CVE-2011-2497

Dan Rosenberg discovered an integer underflow in the Bluetooth subsystem, which could lead to denial of service or privilege escalation.

CVE-2011-2525

Ben Pfaff reported an issue in the network scheduling code. A local user could cause a denial of service (NULL pointer dereference) by sending a specially crafted netlink message.

CVE-2011-2928

Timo Warns discovered that insufficient validation of Be filesystem images could lead to local denial of service if a malformed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.26", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-486", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-4kc-malta", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-5kc-malta", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686-bigmem", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-alpha", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-armel", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-i386", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mips", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mipsel", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-powerpc", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-s390", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-sparc", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-generic", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-legacy", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-smp", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-openvz", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-vserver", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-xen", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-iop32x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-ixp4xx", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-orion5x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc-smp", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r4k-ip22", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-cobalt", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-ip32", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64-smp", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-versatile", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-s390x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-sparc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-486", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-4kc-malta", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-5kc-malta", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686-bigmem", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-generic", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-legacy", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-smp", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-iop32x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-ixp4xx", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-orion5x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc-smp", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r4k-ip22", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-cobalt", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-ip32", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390-tape", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64-smp", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-versatile", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-s390x", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-sparc64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.26", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.26", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.26", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.26-2", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.26", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-686", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny4", rls:"DEB5"))) {
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
