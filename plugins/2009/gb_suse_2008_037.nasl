###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_037.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2008:037
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
tag_insight = "The openSUSE 11.0 kernel was updated to 2.6.25.11-0.1.

  It fixes following security problems:
  CVE-2008-2812: Various tty / serial devices did not check
  function pointers for NULL before calling them, leading to potential
  crashes or code execution.  The devices affected are usually only
  accessible by the root user though.

  CVE-2008-2750: The pppol2tp_recvmsg function in drivers/net/pppol2tp.c
  in the Linux kernel allows remote attackers to cause a denial of
  service (kernel heap memory corruption and system crash) and possibly
  have unspecified other impact via a crafted PPPOL2TP packet that
  results in a large value for a certain length variable.

  CVE-2008-3247: On x86_64 systems, a incorrect buffer size in LDT
  handling might lead to local untrusted attackers causing a crash
  of the machine or potentially execute code with kernel privileges.
  This problem only affects the openSUSE 11.0 kernel, since the problem
  was introduced in the 2.6.25 kernel.

  The update also has lots of other bugfixes that are listed in the
  RPM changelog.

  We previously also released a 2.6.25.9-0.2 kernel but did not
  separately announce it. That update fixed the following security
  problems:

  CVE-2008-2372: A resource starvation issue within mmap was fixed,
  which could have been used by local attackers to hang the machine.

  CVE-2008-2826: A integer overflow in SCTP was fixed, which might have
  been used by remote attackers to crash the machine or potentially
  execute code.";

tag_impact = "local privilege escalation";
tag_affected = "kernel on openSUSE 11.0";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.311164");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-2372", "CVE-2008-2750", "CVE-2008-2812", "CVE-2008-2826", "CVE-2008-3247");
  script_name( "SuSE Update for kernel SUSE-SA:2008:037");

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

if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.25.11~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
