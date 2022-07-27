###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_030.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2008:030
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
tag_insight = "The Linux kernel update was updated on openSUSE 10.2 and 10.3 to fix
  the following security problems:

  CVE-2008-2136: A problem in SIT IPv6 tunnel handling could be used
  by remote attackers to immediately crash the machine.

  CVE-2007-6282: A remote attacker could crash the IPSec/IPv6 stack
  by sending a bad ESP packet. This requires the host to be able to
  receive such packets (default filtered by the firewall).

  CVE-2007-5904: A remote buffer overflow in CIFS was fixed which
  could potentially be used by remote attackers to crash the machine
  or potentially execute code.

  CVE-2008-1615: On x86_64 a denial of service attack could be used by
  local attackers to immediately panic / crash the machine.

  CVE-2008-2358: A security problem in DCCP was fixed, which could be
  used by remote attackers to crash the machine. Only a fix for openSUSE
  10.2 was necessary.

  CVE-2008-2148: The permission checking in sys_utimensat was incorrect
  and local attackers could change the file times of files they do not
  own to the current time.

  CVE-2007-6206: An information leakage during core dumping of root
  processes was fixed. This problem was already fixed for openSUSE 10.3
  previously and was now fixed for openSUSE 10.2.

  CVE-2007-6712: A integer overflow in the hrtimer_forward function
  (hrtimer.c) in Linux kernel, when running on 64-bit systems, allows
  local users to cause a denial of service (infinite loop) via a timer
  with a large expiry value, which causes the timer to always be expired.

  CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk could
  potentially allow local attackers to execute code by timing file
  locking.

  CVE-2008-1367: Clear the &quot;direction&quot; flag before calling signal
  handlers. For specific not yet identified programs under specific
  timing conditions this could potentially have caused memory corruption
  or code execution.

  CVE-2008-1375: Fixed a dnotify race condition, which could be used
  by local attackers to potentially execute code.

  CVE-2007-5500: A ptrace bug could be used by local attackers to hang
  their own processes indefinitely.

  Also various non security bugs were fixed, please see the RPM changelogs.";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 10.2, openSUSE 10.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.307089");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-5500", "CVE-2007-5904", "CVE-2007-6206", "CVE-2007-6282", "CVE-2007-6712", "CVE-2008-0600", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669", "CVE-2008-2136", "CVE-2008-2148", "CVE-2008-2358");
  script_name( "SuSE Update for kernel SUSE-SA:2008:030");

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

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.18~0.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.18~0.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.18~0.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.18~0.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.18~0.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.18~0.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.18~0.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.18.8~0.10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.18.8~0.10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.18.8~0.10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.18.8~0.10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.18.8~0.10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18.8~0.10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.18.8~0.10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
