###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0084_1.nasl 13394 2019-02-01 07:36:10Z mmartin $
#
# SuSE Update for virtualbox openSUSE-SU-2019:0084-1 (virtualbox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.852253");
  script_version("$Revision: 13394 $");
  script_cve_id("CVE-2018-0734", "CVE-2018-11763", "CVE-2018-11784", "CVE-2018-3309",
                "CVE-2019-2446", "CVE-2019-2448", "CVE-2019-2450", "CVE-2019-2451",
                "CVE-2019-2500", "CVE-2019-2501", "CVE-2019-2504", "CVE-2019-2505",
                "CVE-2019-2506", "CVE-2019-2508", "CVE-2019-2509", "CVE-2019-2511",
                "CVE-2019-2520", "CVE-2019-2521", "CVE-2019-2522", "CVE-2019-2523",
                "CVE-2019-2524", "CVE-2019-2525", "CVE-2019-2526", "CVE-2019-2527",
                "CVE-2019-2548", "CVE-2019-2552", "CVE-2019-2553", "CVE-2019-2554",
                "CVE-2019-2555", "CVE-2019-2556");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 08:36:10 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-26 04:02:18 +0100 (Sat, 26 Jan 2019)");
  script_name("SuSE Update for virtualbox openSUSE-SU-2019:0084-1 (virtualbox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2019:0084_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox version 5.2.24 fixes the following issues:

  Update fixes multiple vulnerabilities:

  CVE-2019-2500, CVE-2019-2524, CVE-2019-2552, CVE-2018-3309,
  CVE-2019-2520 CVE-2019-2521, CVE-2019-2522, CVE-2019-2523, CVE-2019-2526,
  CVE-2019-2548 CVE-2018-11763, CVE-2019-2511, CVE-2019-2508, CVE-2019-2509,
  CVE-2019-2527 CVE-2019-2450, CVE-2019-2451, CVE-2019-2555, CVE-2019-2554,
  CVE-2019-2556 CVE-2018-11784, CVE-2018-0734, CVE-2019-2525, CVE-2019-2446,
  CVE-2019-2448 CVE-2019-2501, CVE-2019-2504, CVE-2019-2505, CVE-2019-2506,
  and CVE-2019-2553 (boo#1122212).

  Non-security issues fixed:

  - Linux Additions: fix for building vboxvideo on EL 7.6 standard kernel,
  contributed by Robert Conde

  - USB: fixed a problem causing failures attaching SuperSpeed devices which
  report USB version 3.1 (rather than 3.0) on Windows hosts

  - Audio: added support for surround speaker setups used by Windows 10
  Build 1809

  - Linux hosts: fixed conflict between Debian and Oracle build desktop files

  - Linux guests: fixed building drivers on SLES 12.4

  - Linux guests: fixed building shared folder driver with older kernels


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-84=1");

  script_tag(name:"affected", value:"virtualbox on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-virtualbox-debuginfo", rpm:"python-virtualbox-debuginfo~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.2.24_k4.4.165_81~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-kmp-default-debuginfo", rpm:"virtualbox-guest-kmp-default-debuginfo~5.2.24_k4.4.165_81~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.2.24_k4.4.165_81~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-host-kmp-default-debuginfo", rpm:"virtualbox-host-kmp-default-debuginfo~5.2.24_k4.4.165_81~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.2.24~66.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
