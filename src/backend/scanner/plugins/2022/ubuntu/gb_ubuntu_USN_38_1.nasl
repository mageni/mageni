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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2004.38.1");
  script_cve_id("CVE-2004-0814", "CVE-2004-1016", "CVE-2004-1056", "CVE-2004-1058", "CVE-2004-1068", "CVE-2004-1069", "CVE-2004-1137", "CVE-2004-1151");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-38-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-38-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-38-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta, linux-restricted-modules-2.6.8.1, linux-source-2.6.8.1' package(s) announced via the USN-38-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CAN-2004-0814:

 Vitaly V. Bursov discovered a Denial of Service vulnerability in the 'serio'
 code, opening the same tty device twice and doing some particular operations on
 it caused a kernel panic and/or a system lockup.

 Fixing this vulnerability required a change in the Application Binary
 Interface (ABI) of the kernel. This means that third party user installed
 modules might not work any more with the new kernel, so this fixed kernel got
 a new ABI version number. You have to recompile and reinstall all third party
 modules.

CAN-2004-1016:

 Paul Starzetz discovered a buffer overflow vulnerability in the '__scm_send'
 function which handles the sending of UDP network packets. A wrong validity
 check of the cmsghdr structure allowed a local attacker to modify kernel
 memory, thus causing an endless loop (Denial of Service) or possibly even
 root privilege escalation.

CAN-2004-1056:

 Thomas Hellstrom discovered a Denial of Service vulnerability in the Direct
 Rendering Manager (DRM) drivers. Due to an insufficient DMA lock checking,
 any authorized client could send arbitrary values to the video card, which
 could cause an X server crash or modification of the video output.

CAN-2004-1058:

 Rob Landley discovered a race condition in the handling of /proc/.../cmdline.
 Under very rare circumstances an user could read the environment variables of
 another process that was still spawning. Environment variables are often used
 to pass passwords and other private information to other processes.

CAN-2004-1068:

 A race condition was discovered in the handling of AF_UNIX network packets.
 This reportedly allowed local users to modify arbitrary kernel memory,
 facilitating privilege escalation, or possibly allowing code execution in the
 context of the kernel.

CAN-2004-1069:

 Ross Kendall Axe discovered a possible kernel panic (causing a Denial of
 Service) while sending AF_UNIX network packages if the kernel options
 CONFIG_SECURITY_NETWORK and CONFIG_SECURITY_SELINUX are enabled. This is not
 the case in the kernel packages shipped in Warty Warthog, however, if you
 recompiled the kernel using SELinux, you are affected by this flaw.

CAN-2004-1137:

 Paul Starzetz discovered several flaws in the IGMP handling code. This
 allowed users to provoke a Denial of Service, read kernel memory, and execute
 arbitrary code with root privileges. This flaw is also exploitable remotely
 if an application has bound a multicast socket.

CAN-2004-1151:

 Jeremy Fitzhardinge discovered two buffer overflows in the sys32_ni_syscall()
 and sys32_vm86_warning() functions. This could possibly be exploited to
 overwrite kernel memory with attacker-supplied code and cause root privilege
 escalation.

 This vulnerability only affects the amd64 architecture.");

  script_tag(name:"affected", value:"'linux-meta, linux-restricted-modules-2.6.8.1, linux-source-2.6.8.1' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"fglrx-control", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fglrx-driver-dev", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fglrx-driver", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-386", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-686-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-686", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-generic", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-k8-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-k8", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-xeon", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.8.1", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-386", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-686-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-686", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-amd64-generic", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-amd64-k8-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-amd64-k8", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-amd64-xeon", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-k7-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-k7", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-power3-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-power3", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-power4-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-power4", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-powerpc-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6-powerpc", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-386", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-686-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-686", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-generic", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-k8-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-k8", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-xeon", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-k7-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-k7", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power3-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power3", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power4-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power4", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-powerpc-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-powerpc", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-386", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-686-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-686", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-amd64-generic", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-amd64-k8-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-amd64-k8", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-amd64-xeon", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-k7-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-k7", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-power3-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-power3", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-power4-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-power4", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-powerpc-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6-powerpc", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-386", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-686-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-686", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-generic", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-k8-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-k8", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-xeon", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-k7-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-k7", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power3-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power3", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power4-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power4", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-powerpc-smp", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-powerpc", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-386", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-generic", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-k8-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-k8", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-xeon", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-k7-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-k7", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power3-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power3", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power4-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power4", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-k7-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-k7", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.8.1", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power3-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power3", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power4-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power4", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-powerpc-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-powerpc", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-386", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-686-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-686", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-amd64-generic", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-amd64-k8-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-amd64-k8", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-amd64-xeon", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-k7-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-k7", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-power3-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-power3", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-power4-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-power4", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-powerpc-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6-powerpc", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-386", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-686-smp", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-686", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-amd64-generic", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-amd64-k8-smp", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-amd64-k8", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-amd64-xeon", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-k7-smp", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.8.1-4-k7", ver:"2.6.8.1.3-5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-386", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-686-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-686", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-generic", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-k8-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-k8", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-xeon", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-k7-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-k7", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-power3-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-power3", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-power4-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-power4", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-powerpc-smp", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-powerpc", ver:"2.6.8.1-14", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.8.1", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.8.1", ver:"2.6.8.1-16.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"1.0.6111-1ubuntu8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-glx", ver:"1.0.6111-1ubuntu8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-kernel-source", ver:"1.0.6111-1ubuntu8", rls:"UBUNTU4.10"))) {
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
