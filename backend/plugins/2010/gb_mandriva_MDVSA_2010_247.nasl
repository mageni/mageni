###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDVSA-2010:247 (kernel)
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
tag_insight = "A vulnerability was discovered and corrected in the Linux 2.6 kernel:

  The compat_alloc_user_space functions in include/asm/compat.h files
  in the Linux kernel before 2.6.36-rc4-git2 on 64-bit platforms do
  not properly allocate the userspace memory required for the 32-bit
  compatibility layer, which allows local users to gain privileges by
  leveraging the ability of the compat_mc_getsockopt function (aka the
  MCAST_MSFILTER getsockopt support) to control a certain length value,
  related to a stack pointer underflow issue, as exploited in the wild
  in September 2010. (CVE-2010-3081)
  
  The IA32 system call emulation functionality in
  arch/x86/ia32/ia32entry.S in the Linux kernel before 2.6.36-rc4-git2
  on the x86_64 platform does not zero extend the %eax register after
  the 32-bit entry path to ptrace is used, which allows local users to
  gain privileges by triggering an out-of-bounds access to the system
  call table using the %rax register.  NOTE: this vulnerability exists
  because of a CVE-2007-4573 regression. (CVE-2010-3301)
  
  Integer overflow in the ext4_ext_get_blocks function in
  fs/ext4/extents.c in the Linux kernel before 2.6.34 allows local
  users to cause a denial of service (BUG and system crash) via a
  write operation on the last block of a large file, followed by a sync
  operation. (CVE-2010-3015)
  
  Additionally, the kernel has been updated to the stable version
  2.6.31.14. A timeout bug in bnx2 has been fixed. Muting and unmuting
  on VT1812/VT2002P now should work correctly. A fix for ACL decoding
  on NFS was added. Rebooting on Dell Precision WorkStation T7400 was
  corrected. Read balancing with RAID0 and RAID1 on drives larger then
  2TB was also fixed. A more detailed description is available in the
  package changelog and related tickets.
  
  Thanks to Thomas Backlund and Herton Ronaldo Krzesinski for
  contributions in this update.
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "kernel on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-12/msg00004.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314764");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 08:26:35 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:247");
  script_cve_id("CVE-2010-3081", "CVE-2007-4573", "CVE-2010-3301", "CVE-2010-3015");
  script_name("Mandriva Update for kernel MDVSA-2010:247 (kernel)");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-2.6.31.14-desktop-1mnb", rpm:"broadcom-wl-kernel-2.6.31.14-desktop-1mnb~5.10.91.9~2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-2.6.31.14-desktop586-1mnb", rpm:"broadcom-wl-kernel-2.6.31.14-desktop586-1mnb~5.10.91.9~2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-2.6.31.14-server-1mnb", rpm:"broadcom-wl-kernel-2.6.31.14-server-1mnb~5.10.91.9~2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~5.10.91.9~1.20101125.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~5.10.91.9~1.20101125.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~5.10.91.9~1.20101125.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-2.6.31.14-desktop-1mnb", rpm:"em8300-kernel-2.6.31.14-desktop-1mnb~0.17.4~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-2.6.31.14-desktop586-1mnb", rpm:"em8300-kernel-2.6.31.14-desktop586-1mnb~0.17.4~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-2.6.31.14-server-1mnb", rpm:"em8300-kernel-2.6.31.14-server-1mnb~0.17.4~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-desktop586-latest", rpm:"em8300-kernel-desktop586-latest~0.17.4~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-desktop-latest", rpm:"em8300-kernel-desktop-latest~0.17.4~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-server-latest", rpm:"em8300-kernel-server-latest~0.17.4~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.31.14-desktop-1mnb", rpm:"fglrx-kernel-2.6.31.14-desktop-1mnb~8.650~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.31.14-desktop586-1mnb", rpm:"fglrx-kernel-2.6.31.14-desktop586-1mnb~8.650~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.31.14-server-1mnb", rpm:"fglrx-kernel-2.6.31.14-server-1mnb~8.650~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~8.650~1.20101125.1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~8.650~1.20101125.1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~8.650~1.20101125.1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-2.6.31.14-desktop-1mnb", rpm:"hcfpcimodem-kernel-2.6.31.14-desktop-1mnb~1.19~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-2.6.31.14-desktop586-1mnb", rpm:"hcfpcimodem-kernel-2.6.31.14-desktop586-1mnb~1.19~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-2.6.31.14-server-1mnb", rpm:"hcfpcimodem-kernel-2.6.31.14-server-1mnb~1.19~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-desktop586-latest", rpm:"hcfpcimodem-kernel-desktop586-latest~1.19~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-desktop-latest", rpm:"hcfpcimodem-kernel-desktop-latest~1.19~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-server-latest", rpm:"hcfpcimodem-kernel-server-latest~1.19~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-2.6.31.14-desktop-1mnb", rpm:"hsfmodem-kernel-2.6.31.14-desktop-1mnb~7.80.02.05~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-2.6.31.14-desktop586-1mnb", rpm:"hsfmodem-kernel-2.6.31.14-desktop586-1mnb~7.80.02.05~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-2.6.31.14-server-1mnb", rpm:"hsfmodem-kernel-2.6.31.14-server-1mnb~7.80.02.05~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-desktop586-latest", rpm:"hsfmodem-kernel-desktop586-latest~7.80.02.05~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-desktop-latest", rpm:"hsfmodem-kernel-desktop-latest~7.80.02.05~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-server-latest", rpm:"hsfmodem-kernel-server-latest~7.80.02.05~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586", rpm:"kernel-desktop586~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586-devel", rpm:"kernel-desktop586-devel~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server", rpm:"kernel-server~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server-devel", rpm:"kernel-server-devel~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.31.14~1mnb~1~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.31.14-desktop-1mnb", rpm:"libafs-kernel-2.6.31.14-desktop-1mnb~1.4.11~2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.31.14-desktop586-1mnb", rpm:"libafs-kernel-2.6.31.14-desktop586-1mnb~1.4.11~2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.31.14-server-1mnb", rpm:"libafs-kernel-2.6.31.14-server-1mnb~1.4.11~2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-desktop586-latest", rpm:"libafs-kernel-desktop586-latest~1.4.11~1.20101125.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-desktop-latest", rpm:"libafs-kernel-desktop-latest~1.4.11~1.20101125.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-server-latest", rpm:"libafs-kernel-server-latest~1.4.11~1.20101125.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-2.6.31.14-desktop-1mnb", rpm:"lirc-kernel-2.6.31.14-desktop-1mnb~0.8.6~2.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-2.6.31.14-desktop586-1mnb", rpm:"lirc-kernel-2.6.31.14-desktop586-1mnb~0.8.6~2.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-2.6.31.14-server-1mnb", rpm:"lirc-kernel-2.6.31.14-server-1mnb~0.8.6~2.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-desktop586-latest", rpm:"lirc-kernel-desktop586-latest~0.8.6~1.20101125.2.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-desktop-latest", rpm:"lirc-kernel-desktop-latest~0.8.6~1.20101125.2.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-server-latest", rpm:"lirc-kernel-server-latest~0.8.6~1.20101125.2.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-2.6.31.14-desktop-1mnb", rpm:"lzma-kernel-2.6.31.14-desktop-1mnb~4.43~28mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-2.6.31.14-desktop586-1mnb", rpm:"lzma-kernel-2.6.31.14-desktop586-1mnb~4.43~28mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-2.6.31.14-server-1mnb", rpm:"lzma-kernel-2.6.31.14-server-1mnb~4.43~28mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-desktop586-latest", rpm:"lzma-kernel-desktop586-latest~4.43~1.20101125.28mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-desktop-latest", rpm:"lzma-kernel-desktop-latest~4.43~1.20101125.28mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-server-latest", rpm:"lzma-kernel-server-latest~4.43~1.20101125.28mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.31.14-desktop-1mnb", rpm:"madwifi-kernel-2.6.31.14-desktop-1mnb~0.9.4~4.r4068mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.31.14-desktop586-1mnb", rpm:"madwifi-kernel-2.6.31.14-desktop586-1mnb~0.9.4~4.r4068mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.31.14-server-1mnb", rpm:"madwifi-kernel-2.6.31.14-server-1mnb~0.9.4~4.r4068mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop586-latest", rpm:"madwifi-kernel-desktop586-latest~0.9.4~1.20101125.4.r4068mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop-latest", rpm:"madwifi-kernel-desktop-latest~0.9.4~1.20101125.4.r4068mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-server-latest", rpm:"madwifi-kernel-server-latest~0.9.4~1.20101125.4.r4068mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.31.14-desktop-1mnb", rpm:"nvidia173-kernel-2.6.31.14-desktop-1mnb~173.14.20~7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.31.14-desktop586-1mnb", rpm:"nvidia173-kernel-2.6.31.14-desktop586-1mnb~173.14.20~7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.31.14-server-1mnb", rpm:"nvidia173-kernel-2.6.31.14-server-1mnb~173.14.20~7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.20~1.20101125.7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.20~1.20101125.7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.20~1.20101125.7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.31.14-desktop-1mnb", rpm:"nvidia96xx-kernel-2.6.31.14-desktop-1mnb~96.43.13~7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.31.14-desktop586-1mnb", rpm:"nvidia96xx-kernel-2.6.31.14-desktop586-1mnb~96.43.13~7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.31.14-server-1mnb", rpm:"nvidia96xx-kernel-2.6.31.14-server-1mnb~96.43.13~7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop586-latest", rpm:"nvidia96xx-kernel-desktop586-latest~96.43.13~1.20101125.7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop-latest", rpm:"nvidia96xx-kernel-desktop-latest~96.43.13~1.20101125.7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-server-latest", rpm:"nvidia96xx-kernel-server-latest~96.43.13~1.20101125.7mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.31.14-desktop-1mnb", rpm:"nvidia-current-kernel-2.6.31.14-desktop-1mnb~185.18.36~4mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.31.14-desktop586-1mnb", rpm:"nvidia-current-kernel-2.6.31.14-desktop586-1mnb~185.18.36~4mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.31.14-server-1mnb", rpm:"nvidia-current-kernel-2.6.31.14-server-1mnb~185.18.36~4mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~185.18.36~1.20101125.4mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~185.18.36~1.20101125.4mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~185.18.36~1.20101125.4mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-2.6.31.14-desktop-1mnb", rpm:"slmodem-kernel-2.6.31.14-desktop-1mnb~2.9.11~0.20080817.4.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-2.6.31.14-desktop586-1mnb", rpm:"slmodem-kernel-2.6.31.14-desktop586-1mnb~2.9.11~0.20080817.4.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-2.6.31.14-server-1mnb", rpm:"slmodem-kernel-2.6.31.14-server-1mnb~2.9.11~0.20080817.4.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-desktop586-latest", rpm:"slmodem-kernel-desktop586-latest~2.9.11~1.20101125.0.20080817.4.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-desktop-latest", rpm:"slmodem-kernel-desktop-latest~2.9.11~1.20101125.0.20080817.4.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-server-latest", rpm:"slmodem-kernel-server-latest~2.9.11~1.20101125.0.20080817.4.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-2.6.31.14-desktop-1mnb", rpm:"squashfs-lzma-kernel-2.6.31.14-desktop-1mnb~3.3~11mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-2.6.31.14-desktop586-1mnb", rpm:"squashfs-lzma-kernel-2.6.31.14-desktop586-1mnb~3.3~11mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-2.6.31.14-server-1mnb", rpm:"squashfs-lzma-kernel-2.6.31.14-server-1mnb~3.3~11mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-desktop586-latest", rpm:"squashfs-lzma-kernel-desktop586-latest~3.3~1.20101125.11mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-desktop-latest", rpm:"squashfs-lzma-kernel-desktop-latest~3.3~1.20101125.11mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-server-latest", rpm:"squashfs-lzma-kernel-server-latest~3.3~1.20101125.11mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadditions-kernel-2.6.31.14-desktop-1mnb", rpm:"vboxadditions-kernel-2.6.31.14-desktop-1mnb~3.0.8~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadditions-kernel-2.6.31.14-desktop586-1mnb", rpm:"vboxadditions-kernel-2.6.31.14-desktop586-1mnb~3.0.8~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadditions-kernel-2.6.31.14-server-1mnb", rpm:"vboxadditions-kernel-2.6.31.14-server-1mnb~3.0.8~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~3.0.8~1.20101125.1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~3.0.8~1.20101125.1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~3.0.8~1.20101125.1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-2.6.31.14-desktop-1mnb", rpm:"virtualbox-kernel-2.6.31.14-desktop-1mnb~3.0.8~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-2.6.31.14-desktop586-1mnb", rpm:"virtualbox-kernel-2.6.31.14-desktop586-1mnb~3.0.8~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-2.6.31.14-server-1mnb", rpm:"virtualbox-kernel-2.6.31.14-server-1mnb~3.0.8~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~3.0.8~1.20101125.1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~3.0.8~1.20101125.1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~3.0.8~1.20101125.1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.31.14-desktop-1mnb", rpm:"vpnclient-kernel-2.6.31.14-desktop-1mnb~4.8.02.0030~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.31.14-desktop586-1mnb", rpm:"vpnclient-kernel-2.6.31.14-desktop586-1mnb~4.8.02.0030~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.31.14-server-1mnb", rpm:"vpnclient-kernel-2.6.31.14-server-1mnb~4.8.02.0030~1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop586-latest", rpm:"vpnclient-kernel-desktop586-latest~4.8.02.0030~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop-latest", rpm:"vpnclient-kernel-desktop-latest~4.8.02.0030~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-server-latest", rpm:"vpnclient-kernel-server-latest~4.8.02.0030~1.20101125.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.31.14~1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
