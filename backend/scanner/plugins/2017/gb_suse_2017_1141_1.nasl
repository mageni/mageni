###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1141_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for virtualbox openSUSE-SU-2017:1141-1 (virtualbox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851546");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-05-03 06:46:40 +0200 (Wed, 03 May 2017)");
  script_cve_id("CVE-2017-3513", "CVE-2017-3538", "CVE-2017-3558", "CVE-2017-3559",
                "CVE-2017-3561", "CVE-2017-3563", "CVE-2017-3575", "CVE-2017-3576",
                "CVE-2017-3587");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for virtualbox openSUSE-SU-2017:1141-1 (virtualbox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update to virtualbox 5.0.40 fixes the following issues:

  These security issues were fixed (bsc#1034854):

  - CVE-2017-3513: Vulnerability in the Oracle VM VirtualBox component of
  Oracle Virtualization (subcomponent: Core). Difficult to exploit
  vulnerability allows high privileged attacker with logon to the
  infrastructure where Oracle VM VirtualBox executes to compromise Oracle
  VM VirtualBox. Successful attacks of this vulnerability can result in
  unauthorized read access to a subset of Oracle VM VirtualBox accessible
  data.

  - CVE-2017-3538: Vulnerability in the Oracle VM VirtualBox component of
  Oracle Virtualization (subcomponent: Shared Folder). Difficult to
  exploit vulnerability allows low privileged attacker with logon to the
  infrastructure where Oracle VM VirtualBox executes to compromise Oracle
  VM VirtualBox. Successful attacks of this vulnerability can result in
  unauthorized creation, deletion or modification access to critical data
  or all Oracle VM VirtualBox accessible data as well as unauthorized
  access to critical data or complete access to all Oracle VM VirtualBox
  accessible data.

  - CVE-2017-3558: Vulnerability in the Oracle VM VirtualBox component of
  Oracle Virtualization (subcomponent: Core). Easily exploitable
  vulnerability allows unauthenticated attacker with logon to the
  infrastructure where Oracle VM VirtualBox executes to compromise Oracle
  VM VirtualBox. Successful attacks of this vulnerability can result in
  unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of Oracle VM VirtualBox as well as unauthorized update,
  insert or delete access to some of Oracle VM VirtualBox accessible data
  and unauthorized read access to a subset of Oracle VM VirtualBox
  accessible data.

  - CVE-2017-3559: Vulnerability in the Oracle VM VirtualBox component of
  Oracle Virtualization (subcomponent: Core). Easily exploitable
  vulnerability allows low privileged attacker with logon to the
  infrastructure where Oracle VM VirtualBox executes to compromise Oracle
  VM VirtualBox. Successful attacks of this vulnerability can result in
  unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of Oracle VM VirtualBox as well as unauthorized update,
  insert or delete access to some of Oracle VM VirtualBox accessible data
  and unauthorized read access to a subset of Oracle VM VirtualBox
  accessible data.

  - CVE-2017-3561: Vulnerability in the Oracle VM VirtualBox component of
  Oracle Virtualization (subcomponent: Core). Easily exploitable
  vulnerability allows low privilege ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"virtualbox on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-virtualbox-debuginfo", rpm:"python-virtualbox-debuginfo~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.0.40_k4.1.39_53~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-kmp-default-debuginfo", rpm:"virtualbox-guest-kmp-default-debuginfo~5.0.40_k4.1.39_53~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.0.40_k4.1.39_53~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-kmp-default-debuginfo", rpm:"virtualbox-host-kmp-default-debuginfo~5.0.40_k4.1.39_53~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.0.40~40.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
