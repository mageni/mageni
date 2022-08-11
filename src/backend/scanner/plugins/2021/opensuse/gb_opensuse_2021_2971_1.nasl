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
  script_oid("1.3.6.1.4.1.25623.1.0.854152");
  script_version("2021-09-22T08:01:20+0000");
  script_cve_id("CVE-2019-9755", "CVE-2021-33285", "CVE-2021-33286", "CVE-2021-33287", "CVE-2021-33289", "CVE-2021-35266", "CVE-2021-35267", "CVE-2021-35268", "CVE-2021-35269", "CVE-2021-39251", "CVE-2021-39252", "CVE-2021-39253", "CVE-2021-39255", "CVE-2021-39256", "CVE-2021-39257", "CVE-2021-39258", "CVE-2021-39259", "CVE-2021-39260", "CVE-2021-39261", "CVE-2021-39262", "CVE-2021-39263");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)");
  script_tag(name:"creation_date", value:"2021-09-08 01:02:01 +0000 (Wed, 08 Sep 2021)");
  script_name("openSUSE: Security Advisory for ntfs-3g_ntfsprogs (openSUSE-SU-2021:2971-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2971-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/APJMFOEFTZSFEAKDMRWUM25JNERJUHUT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g_ntfsprogs'
  package(s) announced via the openSUSE-SU-2021:2971-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntfs-3g_ntfsprogs fixes the following issues:

     Update to version 2021.8.22 (bsc#1189720):

  * Fixed compile error when building with libfuse   2.8.0

  * Fixed obsolete macros in configure.ac

  * Signalled support of UTIME_OMIT to external libfuse2

  * Fixed an improper macro usage in ntfscp.c

  * Updated the repository change in the README

  * Fixed vulnerability threats caused by maliciously tampered NTFS
       partitions

  * Security fixes: CVE-2021-33285, CVE-2021-33286, CVE-2021-33287,
       CVE-2021-33289, CVE-2021-35266, CVE-2021-35267, CVE-2021-35268,
       CVE-2021-35269, CVE-2021-39251, CVE-2021-39252, CVE-2021-39253,
       CVE_2021-39254, CVE-2021-39255, CVE-2021-39256, CVE-2021-39257,
       CVE-2021-39258, CVE-2021-39259, CVE-2021-39260, CVE-2021-39261,
       CVE-2021-39262, CVE-2021-39263.

  - Library soversion is now 89

  * Changes in version 2017.3.23

  * Delegated processing of special reparse points to external plugins

  * Allowed kernel caching by lowntfs-3g when not using Posix ACLs

  * Enabled fallback to read-only mount when the volume is hibernated

  * Made a full check for whether an extended attribute is allowed

  * Moved secaudit and usermap to ntfsprogs (now ntfssecaudit and
       ntfsusermap)

  * Enabled encoding broken UTF-16 into broken UTF-8

  * Autoconfigured selecting  sys/sysmacros.h  vs  sys/mkdev

  * Allowed using the full library API on systems without extended
       attributes support

  * Fixed DISABLE_PLUGINS as the condition for not using plugins

  * Corrected validation of multi sector transfer protected records

  * Denied creating/removing files from $Extend

  * Returned the size of locale encoded target as the size of symlinks");

  script_tag(name:"affected", value:"'ntfs-3g_ntfsprogs' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87", rpm:"libntfs-3g87~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87-debuginfo", rpm:"libntfs-3g87-debuginfo~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debuginfo", rpm:"ntfs-3g_ntfsprogs-debuginfo~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debugsource", rpm:"ntfs-3g_ntfsprogs-debugsource~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs", rpm:"ntfsprogs~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-debuginfo", rpm:"ntfsprogs-debuginfo~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra", rpm:"ntfsprogs-extra~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra-debuginfo", rpm:"ntfsprogs-extra-debuginfo~2021.8.22~3.8.1", rls:"openSUSELeap15.3"))) {
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
