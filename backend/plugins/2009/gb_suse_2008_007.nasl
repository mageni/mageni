###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_007.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2008:007
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
tag_insight = "This kernel update fixes the following critical security problem:

  - CVE-2008-0600: A local privilege escalation was found in the
  vmsplice_pipe system call, which could be used by local attackers
  to gain root access.

  This bug affects the following products:
  - openSUSE 10.2 and 10.3
  - SUSE Linux Enterprise Realtime 10 (SP1)

  Fixed packages have been released for openSUSE 10.2 and 10.3.

  For SUSE Linux Enterprise Realtime 10 packages are being prepared
  currently.

  Since this problem affects Linux kernels starting with 2.6.17 and
  vmsplice was not back-ported, no older products are affected.

  - SUSE Linux Enterprise Server 8, 9, and 10: Not affected.
  - SUSE Linux Enterprise Desktop 10: Not affected.
  - Novell Linux Desktop 9: Not affected.
  - SUSE Linux 10.1: Not affected.


  Following minor security problems were fixed additionally:
  - CVE-2007-6206: Core dumps from root might be accessible to the
  wrong owner. This was fixed for openSUSE 10.3 only.

  - CVE-2007-6151: The isdn_ioctl function in isdn_common.c allowed
  local users to cause a denial of service via a crafted ioctl
  struct in which iocts is not null terminated, which triggers a
  buffer overflow. This problem was fixed for openSUSE 10.2.

  And the following bugs were fixed for openSUSE 10.3 (numbers are
  https://bugzilla.novell.com/ references):

  - Update to minor kernel version 2.6.22.17
  - networking bugfixes
  - contains the following patches which were removed:
  - patches.arch/acpica-psd.patch
  - patches.fixes/invalid-semicolon
  - patches.fixes/nopage-range-fix.patch
  - patches.arch/acpi_thermal_blacklist_add_r50p.patch:
  Avoid critical temp shutdowns on specific ThinkPad R50p
  (https://bugzilla.novell.com/show_bug.cgi?id=333043).
  - patches.rt/megasas_IRQF_NODELAY.patch: Convert megaraid SAS
  IRQ to non-threaded IRQ (337489).
  - patches.drivers/libata-implement-force-parameter added to
  series.conf.
  - patches.xen/xen3-fixup-arch-i386: Xen3 i386 build fixes.
  - patches.xen/xenfb-module-param: Re: Patching Xen virtual
  framebuffer.";

tag_impact = "local privilege escalation";
tag_affected = "kernel on openSUSE 10.2, openSUSE 10.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.309834");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0600");
  script_name( "SuSE Update for kernel SUSE-SA:2008:007");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.18.8~0.9", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.18.8~0.9", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.18.8~0.9", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.18.8~0.9", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.18.8~0.9", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18.8~0.9", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.18.8~0.9", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
