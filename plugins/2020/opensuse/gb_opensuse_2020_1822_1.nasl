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
  script_oid("1.3.6.1.4.1.25623.1.0.853554");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2020-15917");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-04 04:01:12 +0000 (Wed, 04 Nov 2020)");
  script_name("openSUSE: Security Advisory for claws-mail (openSUSE-SU-2020:1822-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1822-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00013.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'claws-mail'
  package(s) announced via the openSUSE-SU-2020:1822-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for claws-mail fixes the following issues:

  - Additional cleanup of the template handling

  claws-mail was updated to 3.17.8 (boo#1177967)

  * Shielded template's <pipe>program{} and <pipe>attach_program{} so that the
  command-line that is executed does not allow sequencing such as with
  && <pipe><pipe>, , preventing possible execution of nasty, or at least
  unexpected, commands

  * bug fixes: claws#4376

  * updated English, French, and Spanish manuals

  - Update to 3.17.7

  * Image Viewer: Image attachments, when displayed, are now resized to
  fit the available width rather than the available height.

  * -d is now an alias to --debug.

  * Libravatar plugin: New styles supported: Robohash and Pagan.

  * SpamAssassin plugin: The 'Maximum size' option now matches
  SpamAssassin's maximum, it can now handle messages up to 256MB.

  * LiteHTML viewer plugin: The UI is now translatable. Bug fixes:

  * bug 4313, 'Recursion stack overflow with rebuilding folder tree'

  * bug 4372, '[pl_PL] Crash after 'Send later' without recipient and then
  'Close''

  * bug 4373, 'attach mailto URI double free'

  * bug 4374, 'insert mailto URI misses checks'

  * bug 4384, 'U+00AD (soft hyphen) changed to space in Subject'

  * bug 4386, 'Allow Sieve config without userid without warning'

  * Add missing SSL settings when cloning accounts.

  * Parsing of command-line arguments.

  * PGP Core plugin: fix segv in address completion with a keyring.

  * Libravatar plugin: fixes to image display.

  - Disable python-gtk plugin on suse_version > 1500: still relying
  on python2, which is EOL.

  - Update to 3.17.6:

  * It is now possible to 'Inherit Folder properties and processing rules
  from parent folder' when creating new folders with the move message
  and copy message dialogues.

  * A Phishing warning is now shown when copying a phishing URL, (in
  addition to clicking a phishing URL).

  * The progress window when importing an mbox file is now more responsive.

  * A warning dialogue is shown if the selected privacy system is 'None'
  and automatic signing amd/or encrypting is enabled.

  * Python plugin: pkgconfig is now used to check for python2. This
  enables the Python plugin (which uses python2) to be built on newer
  systems which have both python2 and python3. Bug fixes:

  * bug 3922, 'minimize to tray on startup not working'

  * bug 4220, 'generates files in cache without content'

  * bug 4325, 'Following redirects when retrieving image'

  * bug 4342, 'Import mbox file command doesn't work twice on a row'

  * fix STARTTLS protocol violation

  * fix initial de ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'claws-mail' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-lang", rpm:"claws-mail-lang~3.17.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail", rpm:"claws-mail~3.17.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-debuginfo", rpm:"claws-mail-debuginfo~3.17.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-debugsource", rpm:"claws-mail-debugsource~3.17.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-devel", rpm:"claws-mail-devel~3.17.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"claws-mail", rpm:"claws-mail~3.17.8~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-debuginfo", rpm:"claws-mail-debuginfo~3.17.8~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-debugsource", rpm:"claws-mail-debugsource~3.17.8~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-devel", rpm:"claws-mail-devel~3.17.8~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-lang", rpm:"claws-mail-lang~3.17.8~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
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