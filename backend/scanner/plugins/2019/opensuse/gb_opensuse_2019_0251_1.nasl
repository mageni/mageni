# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852323");
  script_version("$Revision: 13991 $");
  script_cve_id("CVE-2016-5824", "CVE-2018-12405", "CVE-2018-17466", "CVE-2018-18335", "CVE-2018-18356", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18498", "CVE-2018-18500", "CVE-2018-18501", "CVE-2018-18505", "CVE-2018-18509", "CVE-2019-5785");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 11:29:52 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-28 04:07:49 +0100 (Thu, 28 Feb 2019)");
  script_name("SuSE Update for MozillaThunderbird openSUSE-SU-2019:0251-1 (MozillaThunderbird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00069.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2019:0251_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird to version 60.5.1 fixes the following
  issues:

  Security vulnerabilities addressed (MSFA 2019-03 MSFA 2018-31 MFSA
  2019-06  bsc#1122983 bsc#1119105 bsc#1125330):

  - CVE-2018-18356: Fixed a Use-after-free in Skia.

  - CVE-2019-5785: Fixed an Integer overflow in Skia.

  - CVE-2018-18335: Fixed a Buffer overflow in Skia by default deactivating
  Canvas 2D. This issue does not affect Linuc distributions.

  - CVE-2018-18509: Fixed a flaw which during verification of certain S/MIME
  signatures showing mistekenly that emails bring a valid sugnature.

  - CVE-2018-18500: Use-after-free parsing HTML5 stream

  - CVE-2018-18505: Privilege escalation through IPC channel messages

  - CVE-2016-5824 DoS (use-after-free) via a crafted ics file

  - CVE-2018-18501: Memory safety bugs fixed in Firefox 65 and Firefox ESR
  60.5

  - CVE-2018-17466: Buffer overflow and out-of-bounds read in ANGLE library
  with TextureStorage11

  - CVE-2018-18492: Use-after-free with select element

  - CVE-2018-18493: Buffer overflow in accelerated 2D canvas with Skia

  - CVE-2018-18494: Same-origin policy violation using location attribute
  and performance.getEntries to steal cross-origin URLs

  - CVE-2018-18498: Integer overflow when calculating buffer sizes for images

  - CVE-2018-12405: Memory safety bugs fixed in Firefox 64, 60.4, and
  Thunderbird 60.4

  Other bug fixes and changes:

  - FileLink provider WeTransfer to upload large attachments

  - Thunderbird now allows the addition of OpenSearch search engines from a
  local XML file using a minimal user interface: [+] button to select a
  file an add, [-] to remove.

  - More search engines: Google and DuckDuckGo available by default in some
  locales

  - During account creation, Thunderbird will now detect servers using the
  Microsoft Exchange protocol. It will offer the installation of a 3rd
  party add-on (Owl) which supports that protocol.

  - Thunderbird now compatible with other WebExtension-based FileLink
  add-ons like the Dropbox add-on

  - New WebExtensions FileLink API to facilitate add-ons

  - Fix decoding problems for messages with less common charsets (cp932,
  cp936)

  - New messages in the drafts folder (and other special or virtual folders)
  will no longer be included in the new messages notification

  - Thunderbird 60 will migrate security databases (key3.db, cert8.db to
  key4.db, cert9.db).

  - Address book search and auto-complete slowness

  - Plain text markup with * for bold, / for italics, _ for underline and
  for code did not work when the enclosed text contained non-ASCII
  charact ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~60.5.1~lp150.3.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~60.5.1~lp150.3.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~60.5.1~lp150.3.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~60.5.1~lp150.3.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~60.5.1~lp150.3.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~60.5.1~lp150.3.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
