###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_032.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2008:032
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
tag_insight = "The Linux kernel on the SUSE Linux Enterprise 10 Service Pack 1 line
  of products was updated to fix quite a number of security problems:

  CVE-2007-6282: A remote attacker could crash the IPSec/IPv6 stack
  by sending a bad ESP packet. This requires the host to be able to
  receive such packets (default filtered by the firewall).

  CVE-2008-2136: A problem in SIT IPv6 tunnel handling could be used
  by remote attackers to immediately crash the machine.

  CVE-2008-1615: On x86_64 a denial of service attack could be used by
  local attackers to immediately panic / crash the machine.

  CVE-2007-6206: An information leakage during core dumping of root
  processes was fixed.

  CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk could
  potentially allow local attackers to execute code by timing file
  locking.

  CVE-2008-1375: Fixed a dnotify race condition, which could be used
  by local attackers to potentially execute code.

  CVE-2007-5500: A ptrace bug could be used by local attackers to hang
  their own processes indefinitely.

  CVE-2008-1367: Clear the &quot;direction&quot; flag before calling signal
  handlers. For specific not yet identified programs under specific
  timing conditions this could potentially have caused memory corruption
  or code execution.

  CVE-2007-6151: The isdn_ioctl function in isdn_common.c allowed local
  users to cause a denial of service via a crafted ioctl struct in
  which ioctls is not null terminated, which triggers a buffer overflow.


  Non security related changes:

  OCFS2 was updated to version v1.2.9-1-r3100.

  Also a huge number of bugs were fixed. Please refer to the RPM
  changelog for a detailed list.";

tag_impact = "remote denial of service";
tag_affected = "kernel on SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.308529");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-5500", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6282", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669", "CVE-2008-2136");
  script_name( "SuSE Update for kernel SUSE-SA:2008:032");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
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

if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.54~0.2.8", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.54~0.2.8", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.54~0.2.8", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.54~0.2.8", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.54~0.2.8", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.54~0.2.8", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.54~0.2.8", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.54~0.2.8", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.54~0.2.8", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.54~0.2.8", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.54~0.2.8", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.54~0.2.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.54~0.2.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.54~0.2.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.54~0.2.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.54~0.2.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.54~0.2.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.54~0.2.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
