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
  script_oid("1.3.6.1.4.1.25623.1.0.854423");
  script_version("2022-02-22T09:18:02+0000");
  script_cve_id("CVE-2021-41177", "CVE-2021-41178", "CVE-2021-41179");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 14:54:00 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"creation_date", value:"2022-02-08 08:14:47 +0000 (Tue, 08 Feb 2022)");
  script_name("openSUSE: Security Advisory for nextcloud (openSUSE-SU-2021:1602-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1602-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7PNMF4KO3URU5RWGRVFDKVGZD7R2FTUK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2021:1602-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nextcloud fixes the following issues:
  Update to 20.0.14
  Security issues fixed:

  * CVE-2021-41179: Fix boo#1192028 - (CWE-304): Two-Factor Authentication
       not enforced for pages marked as public

  * CVE-2021-41178: Fix boo#1192030 - (CWE-434): File Traversal affecting
       SVG files on Nextcloud Server

  * CVE-2021-41177: Fix boo#1192031 - (CWE-799): Rate-limits not working on
       instances without configured memory cache backend
  Changes:

  - Add command to repair broken filesystem trees (server#26630)

  - Ensure that user and group IDs in LDAP's tables are also max 64chars
       (server#28971)

  - Change output format of Psalm to Github (server#29048)

  - File-upload: Correctly handle error responses for HTTP2 (server#29069)

  - Allow 'TwoFactor Nextcloud Notifications' to pull the state of the 2F
       (server#29072)

  - Add a few sensitive config keys (server#29085)

  - Fix path of file_get_contents (server#29095)

  - Update the certificate bundle (server#29098)

  - Keep pw based auth tokens valid when pw-less login happens (server#29131)

  - Properly handle folder deletion on external s3 storage (server#29158)

  - Tokens without password should not trigger changed password invalidation
       (server#29166)

  - Don't further setup disabled users when logging in with apache
       (server#29167)

  - Add 'supported'-label to all supported apps (server#29181)

  - 21] generate a better optimized query for path prefix search filters
       (server#29192)

  - Keep group restrictions when reenabling apps after an update
       (server#29198)

  - Add proper message to created share not found (server#29205)

  - Add documentation for files_no_background_scan (server#29219)

  - Don't setup the filesystem to check for a favicon we don't use anyway
       (server#29223)

  - Fix background scan doc in config (server#29253)

  - Get `filesize()` if `file_exists()` (server#29290)

  - Fix unable to login errors due to file system not being initialized
       (server#29291)

  - Update 3rdparty ref (server#29297)

  - Bump icewind/streams from 0.7.3 to 0.7.5 in files_external (server#29298)

  - Fix app upgrade (server#29303)

  - Avoid PHP errors when the LDAP attribute is not found (server#29314)

  - Fix security issues when copying groupfolder with advanced ACL
       (server#29366)

  - Scheduling plugin not updating responding attendee status (server#29387)

  - Make calendar schedule options translatable (server#29388)

  - Add whitelist for apps inside of the se ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'nextcloud' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~20.0.14~lp152.3.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-apache", rpm:"nextcloud-apache~20.0.14~lp152.3.15.1", rls:"openSUSELeap15.2"))) {
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