# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854947");
  script_version("2022-09-08T10:11:29+0000");
  script_cve_id("CVE-2022-2850");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-08 10:11:29 +0000 (Thu, 08 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-06 01:02:04 +0000 (Tue, 06 Sep 2022)");
  script_name("openSUSE: Security Advisory for 389-ds (SUSE-SU-2022:3029-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3029-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QIEMQJWA2OATUGUPVOY4RNRWCLKUBW56");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds'
  package(s) announced via the SUSE-SU-2022:3029-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for 389-ds fixes the following issues:

  - CVE-2022-2850: Fixed an application crash when running a sync_repl
       client that could be triggered via a malformed cookie (bsc#1202470).
  Non-security fixes:

  - Update to version 1.4.4.19~git46.c900a28c8:

  * CI - makes replication/acceptance_test.py::test_modify_entry more
         robust

  * UI - LDAP Editor is not updated when we switch instances

  - Improvements to openldap import with password policy present
       (bsc#1199908)

  - Update to version 1.4.4.19~git43.8ba2ea21f:

  * fix covscan

  * BUG - pid file handling

  * Memory leak in slapi_ldap_get_lderrno

  * Need a compatibility option about sub suffix handling

  * Release tarballs don't contain cockpit webapp

  * Replication broken after password change

  * Harden ReplicationManager.wait_for_replication

  * dscontainer: TypeError: unsupported operand type(s) for /: 'str' and
         'int'

  * CLI - dsconf backend export breaks with multiple backends

  * CLI - improve task handling");

  script_tag(name:"affected", value:"'389-ds' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-1.4.4.19", rpm:"389-ds-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debuginfo-1.4.4.19", rpm:"389-ds-debuginfo-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debugsource-1.4.4.19", rpm:"389-ds-debugsource-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-devel-1.4.4.19", rpm:"389-ds-devel-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-1.4.4.19", rpm:"389-ds-snmp-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-debuginfo-1.4.4.19", rpm:"389-ds-snmp-debuginfo-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-1.4.4.19", rpm:"lib389-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-1.4.4.19", rpm:"libsvrcore0-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-debuginfo-1.4.4.19", rpm:"libsvrcore0-debuginfo-1.4.4.19~git46.c900a28c8~150300.3.22.1", rls:"openSUSELeap15.3"))) {
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
