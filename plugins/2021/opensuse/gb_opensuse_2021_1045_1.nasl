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
  script_oid("1.3.6.1.4.1.25623.1.0.853986");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2020-15917");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-16 03:02:16 +0000 (Fri, 16 Jul 2021)");
  script_name("openSUSE: Security Advisory for claws-mail (openSUSE-SU-2021:1045-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1045-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2VE6WDEXX6HETWFB6EGOWAEY6QQSAI6E");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'claws-mail'
  package(s) announced via the openSUSE-SU-2021:1045-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for claws-mail fixes the following issues:

     Update to 3.18.0

  * Support for the OAuth2 authorisation protocol has been added for IMAP,
         POP and SMTP using custom, user-generated client IDs. OAuth2
         preferences are found in the Account Preferences on the Receive page
         (for POP: Authenticate before POP connection, for IMAP: Authentication
         method)  the Send page (SMTP authentication: Authentication method)
         and on a dedicated OAuth2 page.

  * The option &#x27 Save (X-)Face in address book if possible&#x27  has been added
         to the /Message View/Text Options preferences page. Previously the
         (X-)Face would be saved automatically, therefore this option is turned
         on by default.

  * The Image Viewer has been reworked. New options have been added to
         /Message View/Image Viewer: when resizing images, either fit the image
         width or fit the image height to the available space. Fitting the
         image height is the default. Regardless of this setting, when
         displaying images inline they will fit the height. When displaying an
         image, left-clicking the image will toggle between full size and
         reduced size  right-clicking will toggle between fitting the height
         and fitting the width.

  * When re-editing a saved message, it is now possible to use
         /Options/Remove References.

  * It is now possible to attempt to retrieve a missing GPG key via WKD.

  * The man page has been updated.

  * Updated translations: Brazilian Portuguese, British English, Catalan,
         Czech, Danish, Dutch, French, Polish, Romanian, Russian, Slovak,
         Spanish, Traditional Chinese, Turkish.

  * bug fixes: claws#2411, claws#4326, claws#4394, claws#4431, claws#4445,
         claws#4447, claws#4455, claws#4473

  - stop WM&#x27 s X button from causing GPG key fetch attempt

  - Make fancy respect default font size for messageview

  - harden link checker before accepting click

  - non-display of (X-)Face when prefs_common.enable_avatars is
           AVATARS_ENABLE_RENDER (2)

  - debian bug #983778, &#x27 Segfault on selecting empty &#x27 X-Face&#x27  custom
           header&#x27

  * It is now possible to &#x27 Inherit Folder properties and processing rules
         from parent folder&#x27  when creating new folders with the move message
         and copy message dialogues.

  * A Phishing warning is now shown when copying a phishing URL, (in
         addition to clicking a phishing URL).
     ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'claws-mail' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-lang", rpm:"claws-mail-lang~3.18.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail", rpm:"claws-mail~3.18.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-debuginfo", rpm:"claws-mail-debuginfo~3.18.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-debugsource", rpm:"claws-mail-debugsource~3.18.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-devel", rpm:"claws-mail-devel~3.18.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
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