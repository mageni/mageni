###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2295_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for virtualbox openSUSE-SU-2018:2295-1 (virtualbox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852054");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-3005", "CVE-2018-3055", "CVE-2018-3085", "CVE-2018-3086", "CVE-2018-3087", "CVE-2018-3088", "CVE-2018-3089", "CVE-2018-3090", "CVE-2018-3091");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:39:29 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for virtualbox openSUSE-SU-2018:2295-1 (virtualbox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00041.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2018:2295_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox to version 5.2.16 fixes the following issues:

  The following security vulnerabilities were fixed (boo#1101667):

  - CVE-2018-3005: Fixed an easily exploitable vulnerability that allowed
  unauthenticated attacker with logon to the infrastructure where Oracle
  VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful
  attacks of this vulnerability can result in unauthorized ability to
  cause a partial denial
  of service (partial DOS) of Oracle VM VirtualBox.

  - CVE-2018-3055: Fixed an easily exploitable vulnerability that allowed
  unauthenticated attacker with logon to the infrastructure where Oracle
  VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful
  attacks require human interaction from a person other than the attacker
  and while the vulnerability is in Oracle VM VirtualBox, attacks may
  significantly impact additional products. Successful attacks of this
  vulnerability can result in unauthorized ability to cause a hang or
  frequently repeatable crash (complete DOS) of Oracle VM VirtualBox and
  unauthorized read access to a subset of Oracle VM VirtualBox accessible
  data.

  - CVE-2018-3085: Fixed an easily exploitable vulnerability that allowed
  unauthenticated attacker with logon to the infrastructure where Oracle
  VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful
  attacks require human interaction from a person other than the attacker
  and while the vulnerability is in Oracle VM VirtualBox, attacks may
  significantly impact additional products. Successful attacks of this
  vulnerability can result in unauthorized creation, deletion or
  modification access to critical data or all Oracle VM VirtualBox
  accessible data as well as unauthorized read access to a subset of
  Oracle VM VirtualBox accessible data and unauthorized ability to cause a
  hang or frequently repeatable crash (complete DOS) of Oracle VM
  VirtualBox.

  - CVE-2018-3086: Fixed an easily exploitable vulnerability that allowed
  unauthenticated attacker with logon to the infrastructure where Oracle
  VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful
  attacks require human interaction from a person other than the attacker
  and while the vulnerability is in Oracle VM VirtualBox, attacks may
  significantly impact additional products. Successful attacks of this
  vulnerability can result in takeover of Oracle VM VirtualBox.

  - CVE-2018-3087: Fixed an easily exploitable vulnerability that allowed
  unauthenticated attacker with logon to the infrastructure where Oracle
  VM VirtualBox execu ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"virtualbox on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.2.16_k4.12.14_lp150.12.7~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"<br>virtualbox-guest-kmp-default-debuginfo", rpm:"<br>virtualbox-guest-kmp-default-debuginfo~5.2.16_k4.12.14_lp150.12.7~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.2.16_k4.12.14_lp150.12.7~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"<br>virtualbox-host-kmp-default-debuginfo", rpm:"<br>virtualbox-host-kmp-default-debuginfo~5.2.16_k4.12.14_lp150.12.7~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.2.16~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
