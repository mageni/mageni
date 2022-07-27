###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2012:1064-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-July/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870785");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-16 11:52:16 +0530 (Mon, 16 Jul 2012)");
  script_cve_id("CVE-2012-2744", "CVE-2012-2745");
  script_name("RedHat Update for kernel RHSA-2012:1064-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A NULL pointer dereference flaw was found in the nf_ct_frag6_reasm()
  function in the Linux kernel's netfilter IPv6 connection tracking
  implementation. A remote attacker could use this flaw to send
  specially-crafted packets to a target system that is using IPv6 and also
  has the nf_conntrack_ipv6 kernel module loaded, causing it to crash.
  (CVE-2012-2744, Important)

  * A flaw was found in the way the Linux kernel's key management facility
  handled replacement session keyrings on process forks. A local,
  unprivileged user could use this flaw to cause a denial of service.
  (CVE-2012-2745, Moderate)

  Red Hat would like to thank an anonymous contributor working with the
  Beyond Security SecuriTeam Secure Disclosure program for reporting
  CVE-2012-2744.

  This update also fixes the following bugs:

  * Previously introduced firmware files required for new Realtek chipsets
  contained an invalid prefix ('rtl_nic_') in the file names, for example
  '/lib/firmware/rtl_nic/rtl_nic_rtl8168d-1.fw'. This update corrects these
  file names. For example, the aforementioned file is now correctly named
  '/lib/firmware/rtl_nic/rtl8168d-1.fw'. (BZ#832359)

  * This update blacklists the ADMA428M revision of the 2GB ATA Flash Disk
  device. This is due to data corruption occurring on the said device when
  the Ultra-DMA 66 transfer mode is used. When the
  'libata.force=5:pio0, 6:pio0' kernel parameter is set, the aforementioned
  device works as expected. (BZ#832363)

  * On Red Hat Enterprise Linux 6, mounting an NFS export from a server
  running Windows Server 2012 Release Candidate returned the
  NFS4ERR_MINOR_VERS_MISMATCH error because Windows Server 2012 Release
  Candidate supports NFSv4.1 only. Red Hat Enterprise Linux 6 did not
  properly handle the returned error and did not fall back to using NFSv3,
  which caused the mount operation to fail. With this update, when the
  NFS4ERR_MINOR_VERS_MISMATCH error is returned, the mount operation properly
  falls back to using NFSv3 and no longer fails. (BZ#832365)

  * On ext4 file systems, when fallocate() failed to allocate blocks due to
  the ENOSPC condition (no space left on device) for a file larger than 4 GB,
  the size of the file became corrupted and, consequently, caused file system
  corruption. This was due to a mi ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf-debuginfo", rpm:"python-perf-debuginfo~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~279.1.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
