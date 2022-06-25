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
  script_oid("1.3.6.1.4.1.25623.1.0.853860");
  script_version("2021-06-17T06:11:17+0000");
  script_cve_id("CVE-2021-3514");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-06-17 10:43:15 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-15 03:01:44 +0000 (Tue, 15 Jun 2021)");
  script_name("openSUSE: Security Advisory for 389-ds (openSUSE-SU-2021:0868-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0868-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DGKRCMKIKM4Z423PIZY3DK2A4ZMBRUNT");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds'
  package(s) announced via the openSUSE-SU-2021:0868-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for 389-ds fixes the following issues:

  - CVE-2021-3514: Fixed a sync_repl NULL pointer dereference in
       sync_create_state_control() (bsc#1185356)

     389-ds was updated to version 1.4.3.23~git0.f53d0132b:

     Bump version to 1.4.3.23:

  * Issue 4725 - [RFE] DS - Update the password policy to support a
       Temporary Password Rules (#4727)

  * Issue 4759 - Fix coverity issue (#4760)

  * Issue 4656 - Fix cherry pick error around replication enabling

  * Issue 4701 - RFE - Exclude attributes from retro changelog (#4723)
       (#4746)

  * Issue 4742 - UI - should always use LDAPI path when calling CLI

  * Issue 4667 - incorrect accounting of readers in vattr rwlock (#4732)

  * Issue 4711 - SIGSEV with sync_repl (#4738)

  * Issue 4649 - fix testcase importing ContentSyncPlugin

  * Issue 2736 - Warnings from automatic shebang munging macro

  * Issue 4706 - negative wtime in access log for CMP operations

     Bump version to 1.4.3.22:

  * Issue 4671 - UI - Fix browser crashes

  * lib389 - Add ContentSyncPlugin class

  * Issue 4656 - lib389 - fix cherry pick error

  * Issue 4229 - Fix Rust linking

  * Issue 4658 - monitor - connection start date is incorrect

  * Issue 2621 - lib389 - backport ds_supports_new_changelog()

  * Issue 4656 - Make replication CLI backwards compatible with role name
       change

  * Issue 4656 - Remove problematic language from UI/CLI/lib389

  * Issue 4459 - lib389 - Default paths should use dse.ldif if the server is
       down

  * Issue 4663 - CLI - unable to add objectclass/attribute without x-origin

     Bump version to 1.4.3.21:

  * Issue 4169 - UI - updates on the tuning page are not reflected in the UI

  * Issue 4588 - BUG - unable to compile without xcrypt (#4589)

  * Issue 4513 - Fix replication CI test failures (#4557)

  * Issue 4646 - CLI/UI - revise DNA plugin management

  * Issue 4644 - Large updates can reset the CLcache to the beginning of the
       changelog (#4647)

  * Issue 4649 - crash in sync_repl when a MODRDN create a cenotaph (#4652)

  * Issue 4615 - log message when psearch first exceeds max threads per conn

     Bump version to 1.4.3.20:

  * Issue 4324 - Some architectures the cache line size file does not exist

  * Issue 4593 - RFE - Print help when nsSSLPersonalitySSL is not found
       (#4614)

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'389-ds' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-1.4.3.23", rpm:"389-ds-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debuginfo-1.4.3.23", rpm:"389-ds-debuginfo-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debugsource-1.4.3.23", rpm:"389-ds-debugsource-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-devel-1.4.3.23", rpm:"389-ds-devel-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-1.4.3.23", rpm:"389-ds-snmp-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-debuginfo-1.4.3.23", rpm:"389-ds-snmp-debuginfo-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-1.4.3.23", rpm:"lib389-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-1.4.3.23", rpm:"libsvrcore0-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-debuginfo-1.4.3.23", rpm:"libsvrcore0-debuginfo-1.4.3.23~git0.f53d0132b~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
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
