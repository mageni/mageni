###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-2516-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842113");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-01 05:42:49 +0100 (Sun, 01 Mar 2015)");
  script_cve_id("CVE-2015-0239", "CVE-2014-8133", "CVE-2014-8160", "CVE-2014-8559",
                "CVE-2014-8989", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9428",
                "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9683");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-2516-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-2516-1 fixed vulnerabilities in the
Linux kernel. There was an unrelated regression in the use of the virtual counter
(CNTVCT) on arm64 architectures. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

A flaw was discovered in the Kernel Virtual Machine's (KVM) emulation of
the SYSTENTER instruction when the guest OS does not initialize the
SYSENTER MSRs. A guest OS user could exploit this flaw to cause a denial of
service of the guest OS (crash) or potentially gain privileges on the guest
OS. (CVE-2015-0239)

Andy Lutomirski discovered an information leak in the Linux kernel's Thread
Local Storage (TLS) implementation allowing users to bypass the espfix to
obtain information that could be used to bypass the Address Space Layout
Randomization (ASLR) protection mechanism. A local user could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-8133)

A restriction bypass was discovered in iptables when conntrack rules are
specified and the conntrack protocol handler module is not loaded into the
Linux kernel. This flaw can cause the firewall rules on the system to be
bypassed when conntrack rules are used. (CVE-2014-8160)

A flaw was discovered with file renaming in the linux kernel. A local user
could exploit this flaw to cause a denial of service (deadlock and system
hang). (CVE-2014-8559)

A flaw was discovered in how supplemental group memberships are handled in
certain namespace scenarios. A local user could exploit this flaw to bypass
file permission restrictions. (CVE-2014-8989)

A flaw was discovered in how Thread Local Storage (TLS) is handled by the
task switching function in the Linux kernel for x86_64 based machines. A
local user could exploit this flaw to bypass the Address Space Layout
Radomization (ASLR) protection mechanism. (CVE-2014-9419)

Prasad J Pandit reported a flaw in the rock_continue function of the Linux
kernel's ISO 9660 CDROM file system. A local user could exploit this flaw
to cause a denial of service (system crash or hang). (CVE-2014-9420)

A flaw was discovered in the fragment handling of the B.A.T.M.A.N. Advanced
Meshing Protocol in the Linux kernel. A remote attacker could exploit this
flaw to cause a denial of service (mesh-node system crash) via fragmented
packets. (CVE-2014-9428)

A race condition was discovered in the Linux kernel's key ring. A local
user could cause a denial of service (memory corruption or panic) or
possibly have unspecified impact via the keyctl commands. (CVE-2014-9529)

A memory leak was discovered in the ISO 9660 CDROM file system when parsing
 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2516-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"block-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipmi-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipmi-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipmi-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipmi-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipmi-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipmi-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-generic", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-generic-lpae", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-lowlatency", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-powerpc-e500", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-powerpc-e500mc", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-powerpc-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-powerpc64-emb", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-3.13.0-46-powerpc64-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-cloud-tools-common", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-generic", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-generic-lpae", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-lowlatency", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-powerpc-e500", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-powerpc-e500mc", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-powerpc-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-powerpc64-emb", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-3.13.0-46-powerpc64-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-generic", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-generic-lpae", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-lowlatency", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-powerpc-e500", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-powerpc-e500mc", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-powerpc-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-powerpc64-emb", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-46-powerpc64-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-generic", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-generic-lpae", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-lowlatency", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-powerpc-e500", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-powerpc-e500mc", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-powerpc-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-powerpc64-emb", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-extra-3.13.0-46-powerpc64-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source-3.13.0", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-generic", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-generic-lpae", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-lowlatency", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-powerpc-e500", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-powerpc-e500mc", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-powerpc-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-powerpc64-emb", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-3.13.0-46-powerpc64-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-common", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-generic", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-generic-lpae", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-lowlatency", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-powerpc-e500", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-powerpc-e500mc", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-powerpc-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-powerpc64-emb", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-udebs-powerpc64-smp", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"multipath-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"multipath-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"multipath-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"multipath-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"multipath-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"multipath-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"speakup-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"speakup-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"speakup-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"speakup-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"speakup-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"speakup-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-3.13.0-46-generic-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-3.13.0-46-generic-lpae-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-3.13.0-46-powerpc-e500-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-3.13.0-46-powerpc-e500mc-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-3.13.0-46-powerpc-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-3.13.0-46-powerpc64-smp-di", ver:"3.13.0-46.76", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
