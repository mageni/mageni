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
  script_oid("1.3.6.1.4.1.25623.1.0.853914");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2020-29663");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:03:07 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for icinga2 (openSUSE-SU-2021:1029-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1029-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/F7IVRID4FOA6YK4ZLJ273QAN3OEQFE4J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icinga2'
  package(s) announced via the openSUSE-SU-2021:1029-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icinga2 fixes the following issues:

     icinga2 was updated to 2.12.4

  * Bugfixes

  - Fix a crash when notification objects are deleted using the API #8782

  - Fix crashes that might occur during downtime scheduling if host or
           downtime objects are deleted using the API #8785

  - Fix an issue where notifications may incorrectly be skipped after a
           downtime ends #8775

  - Don&#x27 t send reminder notification if the notification is still
           suppressed by a time period #8808

  - Fix an issue where attempting to create a duplicate object using the
           API might result in the original object being deleted #8787

  - IDO: prioritize program status updates #8809

  - Improve exceptions handling, including a fix for an uncaught
           exception on Windows #8777

  - Retry file rename operations on Windows to avoid intermittent
           locking issues #8771

  - Update to 2.12.3

  * Security

  - Fix that revoked certificates due for renewal will automatically be
           renewed ignoring the CRL (Advisory / CVE-2020-29663 - fixes
           boo#1180147 )

  * Bugfixes

  - Improve config sync locking - resolves high load issues on Windows
           #8511

  - Fix runtime config updates being ignored for objects without zone
           #8549

  - Use proper buffer size for OpenSSL error messages #8542

  * Enhancements

  - On checkable recovery: re-check children that have a problem #8506

  - Update to 2.12.2

  * Bugfixes

  - Fix a connection leak with misconfigured agents #8483

  - Properly sync changes of config objects in global zones done via the
           API #8474 #8470

  - Prevent other clients from being disconnected when replaying the
           cluster log takes very long #8496

  - Avoid duplicate connections between endpoints #8465

  - Ignore incoming config object updates for unknown zones #8461

  - Check timestamps before removing files in config sync #8495

  * Enhancements

  - Include HTTP status codes in log #8467");

  script_tag(name:"affected", value:"'icinga2' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"icinga2", rpm:"icinga2~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin", rpm:"icinga2-bin~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin-debuginfo", rpm:"icinga2-bin-debuginfo~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-common", rpm:"icinga2-common~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debuginfo", rpm:"icinga2-debuginfo~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debugsource", rpm:"icinga2-debugsource~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-doc", rpm:"icinga2-doc~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql", rpm:"icinga2-ido-mysql~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql-debuginfo", rpm:"icinga2-ido-mysql-debuginfo~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql", rpm:"icinga2-ido-pgsql~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql-debuginfo", rpm:"icinga2-ido-pgsql-debuginfo~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nano-icinga2", rpm:"nano-icinga2~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-icinga2", rpm:"vim-icinga2~2.12.4~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
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