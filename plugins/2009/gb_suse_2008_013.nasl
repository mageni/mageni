###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_013.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel-rt SUSE-SA:2008:013
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
tag_insight = "The Linux kernel in the SUSE Linux Enterprise Realtime 10 SP1 product
  was updated to fix the following security problems. Our other products have
  already received those fixes.

  - CVE-2008-0001: Incorrect access mode checks could be used by local
  attackers to corrupt directory contents and so cause denial of
  service attacks or potentially execute code.

  - CVE-2008-0600: A local privilege escalation was found in
  the vmsplice_pipe system call, which could be used by local attackers
  to gain root access.

  - CVE-2007-5500: A buggy condition in the ptrace attach logic can
  be used by local attackers to hang the machine.

  - CVE-2007-5501: The tcp_sacktag_write_queue function in
  net/ipv4/tcp_input.c allows remote attackers to cause a denial
  of service (crash) via crafted ACK responses that trigger a NULL
  pointer dereference.

  - CVE-2007-5904: Multiple buffer overflows in CIFS VFS allows remote
  attackers to cause a denial of service (crash) and possibly execute
  arbitrary code via long SMB responses that trigger the overflows
  in the SendReceive function.

  This problem requires the attacker to set up a malicious Samba/CIFS
  server and getting the client to connect to it.

  No other bugs were fixed.";

tag_impact = "local privilege escalation";
tag_affected = "kernel-rt on SUSE Linux Enterprise Server RT Solution 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304505");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-5500", "CVE-2007-5501", "CVE-2007-5904", "CVE-2008-0001", "CVE-2008-0600");
  script_name( "SuSE Update for kernel-rt SUSE-SA:2008:013");

  script_tag(name:"summary", value:"Check for the Version of kernel-rt");
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

if(release == "SLESRTSol10")
{

  if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.22.10~3.8.2", rls:"SLESRTSol10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt_shield_trace", rpm:"kernel-rt_shield_trace~2.6.22.10~3.8.2", rls:"SLESRTSol10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt_timing", rpm:"kernel-rt_timing~2.6.22.10~3.8.2", rls:"SLESRTSol10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.10~3.8.2", rls:"SLESRTSol10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.10~3.8.2", rls:"SLESRTSol10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt_bigsmp", rpm:"kernel-rt_bigsmp~2.6.22.10~3.8.2", rls:"SLESRTSol10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt_bigsmp_shield_trace", rpm:"kernel-rt_bigsmp_shield_trace~2.6.22.10~3.8.2", rls:"SLESRTSol10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
