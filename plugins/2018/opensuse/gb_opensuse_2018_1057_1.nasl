###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1057_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for virtualbox openSUSE-SU-2018:1057-1 (virtualbox)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851734");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-04-25 08:40:14 +0200 (Wed, 25 Apr 2018)");
  script_cve_id("CVE-2017-3737", "CVE-2017-9798", "CVE-2018-0739", "CVE-2018-2830",
                "CVE-2018-2831", "CVE-2018-2835", "CVE-2018-2836", "CVE-2018-2837",
                "CVE-2018-2842", "CVE-2018-2843", "CVE-2018-2844", "CVE-2018-2845",
                "CVE-2018-2860");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for virtualbox openSUSE-SU-2018:1057-1 (virtualbox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for VirtualBox to version 5.1.36 fixes multiple issues:

  Security issues fixed:

  - CVE-2018-0739: Unauthorized remote attacker may have caused a hang or
  frequently repeatable crash (complete DOS)

  - CVE-2018-2830: Attacker with host login may have compromised Virtualbox
  or further system services after interaction with a third user

  - CVE-2018-2831: Attacker with host login may have compromised VirtualBox
  or further system services, allowing read access to some data

  - CVE-2018-2835: Attacker with host login may have gained control over
  VirtualBox and possibly further system services after interacting with a
  third user

  - CVE-2018-2836: Attacker with host login may have gained control over
  VirtualBox and possibly further system services after interacting with a
  third user

  - CVE-2018-2837: Attacker with host login may have gained control over
  VirtualBox and possibly further system services after interacting with a
  third user

  - CVE-2018-2842: Attacker with host login may have gained control over
  VirtualBox and possibly further system services after interacting with a
  third user

  - CVE-2018-2843: Attacker with host login may have gained control over
  VirtualBox and possibly further system services after interacting with a
  third user

  - CVE-2018-2844: Attacker with host login may have gained control over
  VirtualBox and possibly further system services after interacting with a
  third user

  - CVE-2018-2845: Attacker with host login may have caused a hang or
  frequently repeatable crash (complete DOS), and perform unauthorized
  read and write operation to some VirtualBox accessible data

  - CVE-2018-2860: Privileged attacker may have gained control over
  VirtualBox and possibly further system services

  #AppendixOVIR

  This update also contains all upstream fixes and improvements in the
  stable 5.1.36 release.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-389=1");
  script_tag(name:"affected", value:"virtualbox on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-04/msg00069.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018verbose-36781");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-virtualbox-debuginfo", rpm:"python-virtualbox-debuginfo~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.1.36_k4.4.126_48~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-kmp-default-debuginfo", rpm:"virtualbox-guest-kmp-default-debuginfo~5.1.36_k4.4.126_48~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.1.36_k4.4.126_48~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-kmp-default-debuginfo", rpm:"virtualbox-host-kmp-default-debuginfo~5.1.36_k4.4.126_48~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.1.36~50.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
