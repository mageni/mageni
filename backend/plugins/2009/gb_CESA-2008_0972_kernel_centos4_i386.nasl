###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2008:0972 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

  * a flaw was found in the Linux kernel's Direct-IO implementation. This
  could have allowed a local unprivileged user to cause a denial of service.
  (CVE-2007-6716, Important)
  
  * when running ptrace in 31-bit mode on an IBM S/390 or IBM System z
  kernel, a local unprivileged user could cause a denial of service by
  reading from or writing into a padding area in the user_regs_struct32
  structure. (CVE-2008-1514, Important)
  
  * the do_truncate() and generic_file_splice_write() functions did not clear
  the setuid and setgid bits. This could have allowed a local unprivileged
  user to obtain access to privileged information. (CVE-2008-4210, Important)
  
  * Tobias Klein reported a missing check in the Linux kernel's Open Sound
  System (OSS) implementation. This deficiency could have led to an
  information leak. (CVE-2008-3272, Moderate)
  
  * a potential denial of service attack was discovered in the Linux kernel's
  PWC USB video driver. A local unprivileged user could have used this flaw
  to bring the kernel USB subsystem into the busy-waiting state.
  (CVE-2007-5093, Low)
  
  * the ext2 and ext3 file systems code failed to properly handle corrupted
  data structures, leading to a possible local denial of service issue when
  read or write operations were performed. (CVE-2008-3528, Low)
  
  In addition, these updated packages fix the following bugs:
  
  * when using the CIFS &quot;forcedirectio&quot; option, appending to an open file on
  a CIFS share resulted in that file being overwritten with the data to be
  appended.
  
  * a kernel panic occurred when a device with PCI ID 8086:10c8 was present
  on a system with a loaded ixgbe driver.
  
  * due to an aacraid driver regression, the kernel failed to boot when trying
  to load the aacraid driver and printed the following error message:
  &quot;aac_srb: aac_fib_send failed with status: 8195&quot;.
  
  * due to an mpt driver regression, when RAID 1 was configured on Primergy
  systems with an LSI SCSI IME 53C1020/1030 controller, the kernel panicked
  during boot.
  
  * the mpt driver produced a large number of extraneous debugging messages
  when performing a &quot;Host reset&quot; operation.
  
  * due to a regression in the sym driver, the kernel panicked when a SCSI
  hot swap was performed using MCP18 hardware.
  
  * all cores on a multi-core system now scale their frequencies in
  accordance with the policy set by the system's CPU frequency governor.
  
  * the netdump subsystem suffered from several stability issues. These  ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-November/015425.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306710");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_cve_id("CVE-2008-3272", "CVE-2007-6716", "CVE-2007-5093", "CVE-2008-1514", "CVE-2008-3528", "CVE-2008-4210");
  script_name( "CentOS Update for kernel CESA-2008:0972 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~78.0.8.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
