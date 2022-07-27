###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_047.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2008:047
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
tag_insight = "The Linux kernel in the SUSE Linux Enterprise Server 9
  Service Pack 4 was released to fix various bugs and also some security
  problems:

  CVE-2007-6716: Zero the struct dio with kzalloc instead of doing
  it member-wise, this could have leaked information from the kernel.

  CVE-2008-3525: Added missing capability checks in sbni_ioctl().

  CVE-2008-0598: On AMD64 some string operations could leak kernel
  information into user space.

  CVE-2008-1673: Added range checking in ASN.1 handling for the CIFS and
  SNMP NAT netfilter modules.

  CVE-2008-3272: Fixed range checking in the snd_seq OSS ioctl, which
  could be used to leak information from the kernel.

  CVE-2008-2812: Various NULL ptr checks have been added to tty op
  functions, which might have been used by local attackers to execute
  code. We think that this affects only devices openable by root, so the
  impact is limited.

  More details are available in the package changelog.";

tag_impact = "remote denial of service";
tag_affected = "kernel on SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.310698");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6716", "CVE-2008-0598", "CVE-2008-1673", "CVE-2008-2812", "CVE-2008-3272", "CVE-2008-3525");
  script_name( "SuSE Update for kernel SUSE-SA:2008:047");

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

if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-um", rpm:"kernel-um~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"um-host-install-initrd", rpm:"um-host-install-initrd~1.0~48.28", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"um-host-kernel", rpm:"um-host-kernel~2.6.5~7.314", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-um", rpm:"kernel-um~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"um-host-install-initrd", rpm:"um-host-install-initrd~1.0~48.28", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"um-host-kernel", rpm:"um-host-kernel~2.6.5~7.314", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
