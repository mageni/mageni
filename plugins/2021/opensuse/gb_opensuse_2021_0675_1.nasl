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
  script_oid("1.3.6.1.4.1.25623.1.0.853798");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2020-14929");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-07 03:02:36 +0000 (Fri, 07 May 2021)");
  script_name("openSUSE: Security Advisory for alpine (openSUSE-SU-2021:0675-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0675-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7ZRQIHG7XRVXHNCK66IMEPQ7LPQIJT4P");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'alpine'
  package(s) announced via the openSUSE-SU-2021:0675-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for alpine fixes the following issues:

     Update to release 2.24

  * A few crash fixes

  * Implementation of XOAUTH2 for Yahoo! Mail.

     Update to release 2.23.2

  * Expansion of the configuration screen for XOAUTH2 to include username,
       and tenant.

  * Alpine uses the domain in the From: header of a message to generate a
       message-id and suppresses all information about Alpine, version,
       revision, and time of generation
       of the message-id from this header.

  * Alpine does not generate Sender or X-X-Sender by default by enabling [X]
       Disable Sender as the default.

  * Alpine does not disclose User Agent by default by enabling [X] Suppress
       User Agent by default.

  * When messages are selected, pressing the &#x27  &#x27  command to broaden or
       narrow a search, now offers the possibility to completely replace the
       search, and is almost equivalent to being a shortcut to 'unselect all
       messages, and select again'.

     Update to release 2.23

  * Fixes boo#1173281, CVE-2020-14929: Alpine silently proceeds to use an
       insecure connection after a /tls is sent in certain circumstances.

  * Implementation of XOAUTH2 authentication support for Outlook.

  * Add support for the OAUTHBEARER authentication method in Gmail.

  * Support for the SASL-IR IMAP extension.

  * Alpine can pass an HTML message to an external web browser, by using the
       'External' command in the ATTACHMENT INDEX screen.

     Update to release 2.22

  * Support for XOAUTH2 authentication method in Gmail.

  * NTLM authentication support with the ntlm library.

  * Added the '/tls1_3' flag for servers that support it.

  * Add the 'g' option to the select command that works in IMAP servers that
       implement the X-GM-EXT-1 capability (such as the
       one offered by Gmail).

  * Added '/auth=XYZ' to the way to define a server. This allows users to
       select the method to authenticate to an IMAP, SMTP
       or POP3 server. Examples are /auth=plain, or /auth=gssapi, etc.

  * When a message is of type multipart/mixed, and its first part is
       multipart/signed, Alpine will include the text of the
       original message in a reply message, instead of including a multipart
        attachment.

  * Added backward search in the index screen.

  * pico: Add -dict option to Pico, which allows users to choose a
       dictionary when spelling.

  - Drop /usr/bin/mailutil, it is not built by default anymore.

  * Added Quota subcommands for printing, forwarding, saving, etc.");

  script_tag(name:"affected", value:"'alpine' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"alpine", rpm:"alpine~2.24~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"alpine-debuginfo", rpm:"alpine-debuginfo~2.24~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"alpine-debugsource", rpm:"alpine-debugsource~2.24~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pico", rpm:"pico~5.07~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pico-debuginfo", rpm:"pico-debuginfo~5.07~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pilot", rpm:"pilot~2.99~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pilot-debuginfo", rpm:"pilot-debuginfo~2.99~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
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