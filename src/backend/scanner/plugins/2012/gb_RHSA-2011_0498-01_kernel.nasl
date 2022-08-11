###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2011:0498-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870632");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:37:21 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-4250", "CVE-2010-4565", "CVE-2010-4649", "CVE-2011-0006",
                "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1013",
                "CVE-2011-1016", "CVE-2011-1019", "CVE-2011-1044", "CVE-2011-1079",
                "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1573");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("RedHat Update for kernel RHSA-2011:0498-01");

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

  Security fixes:

  * An integer overflow flaw in ib_uverbs_poll_cq() could allow a local,
  unprivileged user to cause a denial of service or escalate their
  privileges. (CVE-2010-4649, Important)

  * An integer signedness flaw in drm_modeset_ctl() could allow a local,
  unprivileged user to cause a denial of service or escalate their
  privileges. (CVE-2011-1013, Important)

  * The Radeon GPU drivers in the Linux kernel were missing sanity checks for
  the Anti Aliasing (AA) resolve register values which could allow a local,
  unprivileged user to cause a denial of service or escalate their privileges
  on systems using a graphics card from the ATI Radeon R300, R400, or R500
  family of cards. (CVE-2011-1016, Important)

  * A flaw in dccp_rcv_state_process() could allow a remote attacker to
  cause a denial of service, even when the socket was already closed.
  (CVE-2011-1093, Important)

  * A flaw in the Linux kernel's Stream Control Transmission Protocol (SCTP)
  implementation could allow a remote attacker to cause a denial of service
  if the sysctl 'net.sctp.addip_enable' and 'auth_enable' variables were
  turned on (they are off by default). (CVE-2011-1573, Important)

  * A memory leak in the inotify_init() system call. In some cases, it could
  leak a group, which could allow a local, unprivileged user to eventually
  cause a denial of service. (CVE-2010-4250, Moderate)

  * A missing validation of a null-terminated string data structure element
  in bnep_sock_ioctl() could allow a local user to cause an information leak
  or a denial of service. (CVE-2011-1079, Moderate)

  * An information leak in bcm_connect() in the Controller Area Network (CAN)
  Broadcast Manager implementation could allow a local, unprivileged user to
  leak kernel mode addresses in '/proc/net/can-bcm'. (CVE-2010-4565, Low)

  * A flaw was found in the Linux kernel's Integrity Measurement Architecture
  (IMA) implementation. When SELinux was disabled, adding an IMA rule which
  was supposed to be processed by SELinux would cause ima_match_rules() to
  always succeed, ignoring any remaining rules. (CVE-2011-0006, Low)

  * A missing initialization flaw in the XFS file system implementation could
  lead to an information leak. (CVE-2011-0711, Low)

  * Buffer overflow flaws in snd_usb_caiaq_audio_init() and
  snd_usb_caiaq_midi_init() could allow a l ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~71.29.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
