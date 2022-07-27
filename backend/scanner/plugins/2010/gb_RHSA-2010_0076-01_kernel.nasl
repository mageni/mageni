###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2010:0076-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:
  
  * an array index error was found in the gdth driver in the Linux kernel. A
  local user could send a specially-crafted IOCTL request that would cause a
  denial of service or, possibly, privilege escalation. (CVE-2009-3080,
  Important)
  
  * a flaw was found in the collect_rx_frame() function in the HiSax ISDN
  driver (hfc_usb) in the Linux kernel. An attacker could use this flaw to
  send a specially-crafted HDLC packet that could trigger a buffer out of
  bounds, possibly resulting in a denial of service. (CVE-2009-4005,
  Important)
  
  * permission issues were found in the megaraid_sas driver (for SAS based
  RAID controllers) in the Linux kernel. The &quot;dbg_lvl&quot; and &quot;poll_mode_io&quot;
  files on the sysfs file system (&quot;/sys/&quot;) had world-writable permissions.
  This could allow local, unprivileged users to change the behavior of the
  driver. (CVE-2009-3889, CVE-2009-3939, Moderate)
  
  * a buffer overflow flaw was found in the hfs_bnode_read() function in the
  HFS file system implementation in the Linux kernel. This could lead to a
  denial of service if a user browsed a specially-crafted HFS file system,
  for example, by running &quot;ls&quot;. (CVE-2009-4020, Low)
  
  This update also fixes the following bugs:
  
  * if a process was using ptrace() to trace a multi-threaded process, and
  that multi-threaded process dumped its core, the process performing the
  trace could hang in wait4(). This issue could be triggered by running
  &quot;strace -f&quot; on a multi-threaded process that was dumping its core,
  resulting in the strace command hanging. (BZ#555869)
  
  * a bug in the ptrace() implementation could have, in some cases, caused
  ptrace_detach() to create a zombie process if the process being traced
  was terminated with a SIGKILL signal. (BZ#555869)
  
  * the RHSA-2010:0020 update resolved an issue (CVE-2009-4537) in the
  Realtek r8169 Ethernet driver. This update implements a better solution for
  that issue. Note: This is not a security regression. The original fix was
  complete. This update is adding the official upstream fix. (BZ#556406)
  
  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.";

tag_affected = "kernel on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-February/msg00000.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313085");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-08 11:34:22 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2010:0076-01");
  script_cve_id("CVE-2009-3080", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4005", "CVE-2009-4020", "CVE-2009-4537");
  script_name("RedHat Update for kernel RHSA-2010:0076-01");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~89.0.20.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
