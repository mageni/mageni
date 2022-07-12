###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_052.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2008:052
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
tag_insight = "The openSUSE 10.3 kernel was update to 2.6.22.19. This includes bugs
  and security fixes.

  CVE-2008-4576: Fixed a crash in SCTP INIT-ACK, on mismatch between
  SCTP AUTH availability. This might be exploited remotely for a denial
  of service (crash) attack.

  CVE-2008-3528: The ext[234] filesystem code fails to properly handle
  corrupted data structures. With a mounted filesystem image or partition
  that have corrupted dir-&gt;i_size and dir-&gt;i_blocks, a user performing
  either a read or write operation on the mounted image or partition
  can lead to a possible denial of service by spamming the logfile.

  CVE-2007-6716: fs/direct-io.c in the dio subsystem in the Linux kernel
  did not properly zero out the dio struct, which allows local users
  to cause a denial of service (OOPS), as demonstrated by a certain
  fio test.

  CVE-2008-3525: Added missing capability checks in sbni_ioctl().

  CVE-2008-3272: Fixed range checking in the snd_seq OSS ioctl, which
  could be used to leak information from the kernel.

  CVE-2008-3276: An integer overflow flaw was found in the Linux kernel
  dccp_setsockopt_change() function. An attacker may leverage this
  vulnerability to trigger a kernel panic on a victim's machine remotely.

  CVE-2008-1673: Added range checking in ASN.1 handling for the CIFS
  and SNMP NAT netfilter modules.

  CVE-2008-2826: A integer overflow in SCTP was fixed, which might have
  been used by remote attackers to crash the machine or potentially
  execute code.

  CVE-2008-2812: Various NULL ptr checks have been added to tty op
  functions, which might have been used by local attackers to execute
  code. We think that this affects only devices openable by root,
  so the impact is limited.";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 10.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.310247");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6716", "CVE-2008-1673", "CVE-2008-2812", "CVE-2008-2826", "CVE-2008-3272", "CVE-2008-3276", "CVE-2008-3525", "CVE-2008-3528", "CVE-2008-4576");
  script_name( "SuSE Update for kernel SUSE-SA:2008:052");

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

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
