###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1193 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-August/016062.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880777");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-5966", "CVE-2009-1385", "CVE-2009-1388", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
  script_name("CentOS Update for kernel CESA-2009:1193 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * the possibility of a timeout value overflow was found in the Linux kernel
  high-resolution timers functionality, hrtimers. This could allow a local,
  unprivileged user to execute arbitrary code, or cause a denial of service
  (kernel panic). (CVE-2007-5966, Important)

  * a flaw was found in the Intel PRO/1000 network driver in the Linux
  kernel. Frames with sizes near the MTU of an interface may be split across
  multiple hardware receive descriptors. Receipt of such a frame could leak
  through a validation check, leading to a corruption of the length check. A
  remote attacker could use this flaw to send a specially-crafted packet that
  would cause a denial of service or code execution. (CVE-2009-1385,
  Important)

  * Michael Tokarev reported a flaw in the Realtek r8169 Ethernet driver in
  the Linux kernel. This driver allowed interfaces using this driver to
  receive frames larger than could be handled, which could lead to a remote
  denial of service or code execution. (CVE-2009-1389, Important)

  * the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared when a
  setuid or setgid program was executed. A local, unprivileged user could use
  this flaw to bypass the mmap_min_addr protection mechanism and perform a
  NULL pointer dereference attack, or bypass the Address Space Layout
  Randomization (ASLR) security feature. (CVE-2009-1895, Important)

  * Ramon de Carvalho Valle reported two flaws in the Linux kernel eCryptfs
  implementation. A local attacker with permissions to perform an eCryptfs
  mount could modify the metadata of the files in that eCrypfts mount to
  cause a buffer overflow, leading to a denial of service or privilege
  escalation. (CVE-2009-2406, CVE-2009-2407, Important)

  * Konstantin Khlebnikov discovered a race condition in the ptrace
  implementation in the Linux kernel. This race condition can occur when the
  process tracing and the process being traced participate in a core dump. A
  local, unprivileged user could use this flaw to trigger a deadlock,
  resulting in a partial denial of service. (CVE-2009-1388, Moderate)

  Bug fixes:

  * possible host (dom0) crash when installing a Xen para-virtualized guest
  while another para-virtualized guest was rebooting. (BZ#497812)

  * no audit record for a directory removal if the directory and its subtree
  were recursively watched by an audit rule. (BZ#507561)

  * running 'echo 1 > /proc/sys/vm/drop_caches' on systems under high memory
  load could cause ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.4.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
