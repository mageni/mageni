# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853488");
  script_version("2020-10-15T06:59:23+0000");
  script_cve_id("CVE-2020-8154", "CVE-2020-8155", "CVE-2020-8183", "CVE-2020-8228", "CVE-2020-8233");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-15 11:08:37 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-11 03:00:53 +0000 (Sun, 11 Oct 2020)");
  script_name("openSUSE: Security Advisory for nextcloud (openSUSE-SU-2020:1652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1652-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00019.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2020:1652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nextcloud fixes the following issues:

  nextcloud version 20.0.0 fix some security issues:

  - NC-SA-2020-037 PIN for passwordless WebAuthm is asked for but not
  verified

  - NC-SA-2020-033 (CVE-2020-8228) Missing rate limit on signup page

  - NC-SA-2020-029 (CVE-2020-8233, boo#1177346) Re-Sharing allows increase
  of privileges

  - NC-SA-2020-026 Password of share by mail is not hashed when given on
  the create share call

  - NC-SA-2020-023 Increase random used for encryption

  - Update to 19.0.3

  - Fix possible leaking scope in Flow (server#22410)

  - Combine body-login rules in theming and fix twofactor and guest
  styling on bright colors (server#22427)

  - Show better quota warning for group folders and external storage
  (server#22442)

  - Add php docs build script (server#22448)

  - Fix clicks on actions menu of non opaque file rows in acceptance tests
  (server#22503)

  - Fix writing BLOBs to postgres with recent contacts interaction
  (server#22515)

  - Set the mount id before calling storage wrapper (server#22519)

  - Fix S3 error handling (server#22521)

  - Only disable zip64 if the size is known (server#22537)

  - Change free space calculation (server#22553)

  - Do not keep the part file if the forbidden exception has no retry set
  (server#22560)

  - Fix app password updating out of bounds (server#22569)

  - Use the correct root to determinate the webroot for the resource
  (server#22579)

  - Upgrade icewind/smb to 3.2.7 (server#22581)

  - Bump elliptic from 6.4.1 to 6.5.3 (notifications#732)

  - Fixes regression that prevented you from toggling the encryption flag
  (privacy#489)

  - Match any non-whitespace character in filesystem pattern
  (serverinfo#229)

  - Catch StorageNotAvailable exceptions (text#1001)

  - Harden read only check on public endpoints (text#1017)

  - Harden check when using token from memcache (text#1020)

  - Sessionid is an int (text#1029)

  - Only overwrite Ctrl-f when text is focused (text#990)

  - Set the X-Requested-With header on dav requests (viewer#582)

  - Update to 19.0.2

  - [stable19] lower minimum search length to 2 characters (server#21782)

  - [stable19] Call openssl_pkey_export with $config and log errors.
  (server#21804)

  - [stable19] Improve error reporting on sharing errors (server#21806)

  - [stable19] Do not log RequestedRangeNotSatisfiable exceptions in DAV
  (server#21840)

  - [stable19] Fix parsing of language code (server#21857)

  - [stable19] fix typo in revokeShare() (server#21876)

  - [stable19] Discourage webauthn user interaction (server#21917)

  - [stable19] Encryption is ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'nextcloud' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~20.0.0~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~20.0.0~lp151.2.9.1", rls:"openSUSELeap15.1"))) {
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
