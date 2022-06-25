###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_053.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2008:053
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
tag_insight = "This patch updates the openSUSE 11.0 kernel to the 2.6.25.18 stable
  release.

  It also includes bugfixes and security fixes:

  CVE-2008-4410: The vmi_write_ldt_entry function in
  arch/x86/kernel/vmi_32.c in the Virtual Machine Interface (VMI) in the
  Linux kernel 2.6.26.5 invokes write_idt_entry where write_ldt_entry
  was intended, which allows local users to cause a denial of service
  (persistent application failure) via crafted function calls, related
  to the Java Runtime Environment (JRE) experiencing improper LDT
  selector state.

  CVE-2008-4618: Fixed a kernel panic in SCTP while process protocol
  violation parameter.

  CVE-2008-3528: The ext[234] filesystem code fails to properly handle
  corrupted data structures. With a mounted filesystem image or partition
  that have corrupted dir-&gt;i_size and dir-&gt;i_blocks, a user performing
  either a read or write operation on the mounted image or partition
  can lead to a possible denial of service by spamming the logfile.

  CVE-2008-3526: Integer overflow in the sctp_setsockopt_auth_key
  function in net/sctp/socket.c in the Stream Control Transmission
  Protocol (sctp) implementation in the Linux kernel allows remote
  attackers to cause a denial of service (panic) or possibly have
  unspecified other impact via a crafted sca_keylength field associated
  with the SCTP_AUTH_KEY option.

  CVE-2008-3525: Added missing capability checks in sbni_ioctl().

  CVE-2008-4576: SCTP in Linux kernel before 2.6.25.18 allows remote
  attackers to cause a denial of service (OOPS) via an INIT-ACK
  that states the peer does not support AUTH, which causes the
  sctp_process_init function to clean up active transports and triggers
  the OOPS when the T1-Init timer expires.

  CVE-2008-4445: The sctp_auth_ep_set_hmacs function in net/sctp/auth.c
  in the Stream Control Transmission Protocol (sctp) implementation
  in the Linux kernel before 2.6.26.4, when the SCTP-AUTH extension
  is enabled, does not verify that the identifier index is within the
  bounds established by SCTP_AUTH_HMAC_ID_MAX, which allows local users
  to obtain sensitive information via a crafted SCTP_HMAC_IDENT IOCTL
  request involving the sctp_getsockopt function.

  CVE-2008-3792: net/sctp/socket.c in the Stream Control Transmission
  Pro ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 11.0";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.307336");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-3525", "CVE-2008-3526", "CVE-2008-3528", "CVE-2008-3792", "CVE-2008-3911", "CVE-2008-4113", "CVE-2008-4410", "CVE-2008-4445", "CVE-2008-4576", "CVE-2008-4618");
  script_name( "SuSE Update for kernel SUSE-SA:2008:053");

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

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.25.18~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
