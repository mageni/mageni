# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.854340");
  script_version("2021-12-03T04:02:27+0000");
  script_cve_id("CVE-2019-3687", "CVE-2019-3688", "CVE-2020-8013");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-03 02:03:34 +0000 (Fri, 03 Dec 2021)");
  script_name("openSUSE: Security Advisory for permissions (openSUSE-SU-2021:1520-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1520-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CDE67H3SKCA2N6SED6KU5T3MBX3UVI6N");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'permissions'
  package(s) announced via the openSUSE-SU-2021:1520-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for permissions fixes the following issues:

     Update to version 20200127:

  * Makefile: Leap 15.3 still uses /etc, so adjust the installation setup

     Update to version 20181225:

  * mgetty: faxq-helper now finally reside in /usr/libexec

  * libksysguard5: Updated path for ksgrd_network_helper

  * kdesu: Updated path for kdesud

  * sbin_dirs cleanup: these binaries have already been moved to /usr/sbin

  * mariadb: revert auth_pam_tool to /usr/lib{, 64} again

  * cleanup: revert virtualbox back to plain /usr/lib

  * cleanup: remove deprecated /etc/ssh/sshd_config

  * hawk_invoke is not part of newer hawk2 packages anymore

  * cleanup: texlive-filesystem: public now resides in libexec

  * cleanup: authbind: helper now resides in libexec

  * cleanup: polkit: the agent now also resides in libexec

  * libexec cleanup: &#x27 inn&#x27  news binaries now reside in libexec

  * whitelist please (boo#1183669)

  * Fix enlightenment paths

  * usbauth: drop compatibility variable for libexec

  * usbauth: Updated path for usbauth-npriv

  * profiles: finish usage of variable for polkit-agent-helper-1

  * Makefile: fix custom flags support when using make command line variables

  * added information about know limitations of this approach

  * Makefile: compile with LFO support to fix 32-bit emulation on 64-bit
       hosts (boo#1178476)

  * Makefile: support CXXFLAGS and LDFLAGS override / extension via make/env
       variables (boo#1178475)

  * profiles: prepare /usr/sbin versions of profile entries (boo#1029961)

  * profiles: use new variables feature to remove redundant entries

  * profiles: remove now superfluous squid pinger paths (boo#1171569)

  * tests: implement basic tests for new the new variable feature

  * tests: avoid redundant specification of test names by using class names

  * regtests: split up base types and actual test implementation

  * man pages: add documentation about variables, update copyrights

  * chkstat: implement support for variables in profile paths

  * chkstat: prepare reuse of config file locations

  * chkstat: fix some typos and whitespace

  * etc/permissions: remove unnecessary, duplicate, outdated entries

  * etc/permissions: remove trailing whitespace

  * ksgrd_network_helper: remove obviously wrong path

  * adjust squid pinger path (boo#1171569)

  * mgetty: remove long dead (or never existing) locks directory
       (boo#1171882)

  * squid: remove basic_pam_auth which doesn&#x27 t need special perms
       (boo#1171569)

  * ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'permissions' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~20200127~lp153.24.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debuginfo", rpm:"permissions-debuginfo~20200127~lp153.24.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debugsource", rpm:"permissions-debugsource~20200127~lp153.24.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-zypp-plugin", rpm:"permissions-zypp-plugin~20200127~lp153.24.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);