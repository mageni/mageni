###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2018_0013-01_microcode_ctl.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for microcode_ctl RHSA-2018:0013-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812600");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-05 23:53:49 +0100 (Fri, 05 Jan 2018)");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for microcode_ctl RHSA-2018:0013-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The microcode_ctl packages provide microcode
  updates for Intel and AMD processors. Security Fix(es): * An industry-wide issue
  was found in the way many modern microprocessor designs have implemented
  speculative execution of instructions (a commonly used performance
  optimization). There are three primary variants of the issue which differ in the
  way the speculative execution can be exploited. Variant CVE-2017-5715 triggers
  the speculative execution by utilizing branch target injection. It relies on the
  presence of a precisely-defined instruction sequence in the privileged code as
  well as the fact that memory accesses may cause allocation into the
  microprocessor's data cache even for speculatively executed instructions that
  never actually commit (retire). As a result, an unprivileged attacker could use
  this flaw to cross the syscall and guest/host boundaries and read privileged
  memory by conducting targeted cache side-channel attacks. (CVE-2017-5715) Note:
  This is the microcode counterpart of the CVE-2017-5715 kernel mitigation. Red
  Hat would like to thank Google Project Zero for reporting this issue.");
  script_tag(name:"affected", value:"microcode_ctl on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2018-January/msg00009.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~1.17~25.2.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"microcode_ctl-debuginfo", rpm:"microcode_ctl-debuginfo~1.17~25.2.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
