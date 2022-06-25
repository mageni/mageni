###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_0323_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for Mozilla openSUSE-SU-2013:0323-1 (Mozilla)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2013-02/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850405");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:28 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774",
                "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0777", "CVE-2013-0778",
                "CVE-2013-0779", "CVE-2013-0780", "CVE-2013-0781", "CVE-2013-0782",
                "CVE-2013-0783");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for Mozilla openSUSE-SU-2013:0323-1 (Mozilla)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.1");
  script_tag(name:"affected", value:"Mozilla on openSUSE 12.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"MozillaFirefox was updated to Firefox 19.0 (bnc#804248)
  MozillaThunderbird was updated to Thunderbird 17.0.3
  (bnc#804248) seamonkey was updated to SeaMonkey 2.16
  (bnc#804248) xulrunner was updated to 17.0.3esr
  (bnc#804248) chmsee was updated to version 2.0.

  Changes in MozillaFirefox 19.0:

  * MFSA 2013-21/CVE-2013-0783/2013-0784 Miscellaneous
  memory safety hazards

  * MFSA 2013-22/CVE-2013-0772 (bmo#801366) Out-of-bounds
  read in image rendering

  * MFSA 2013-23/CVE-2013-0765 (bmo#830614) Wrapped WebIDL
  objects can be wrapped again

  * MFSA 2013-24/CVE-2013-0773 (bmo#809652) Web content
  bypass of COW and SOW security wrappers

  * MFSA 2013-25/CVE-2013-0774 (bmo#827193) Privacy leak in
  JavaScript Workers

  * MFSA 2013-26/CVE-2013-0775 (bmo#831095) Use-after-free
  in nsImageLoadingContent

  * MFSA 2013-27/CVE-2013-0776 (bmo#796475) Phishing on
  HTTPS connection through malicious proxy

  * MFSA 2013-28/CVE-2013-0780/CVE-2013-0782/CVE-2013-0777/
  CVE-2013-0778/CVE-2013-0779/CVE-2013-0781
  Use-after-free, out of bounds read, and buffer overflow
  issues found using Address Sanitizer

  - removed obsolete patches

  * mozilla-webrtc.patch

  * mozilla-gstreamer-803287.patch

  - added patch to fix session restore window order
  (bmo#712763)

  - update to Firefox 18.0.2

  * blocklist and CTP updates

  * fixes in JS engine

  - update to Firefox 18.0.1

  * blocklist updates

  * backed out bmo#677092 (removed patch)

  * fixed problems involving HTTP proxy transactions

  - Fix WebRTC to build on powerpc

  Changes in MozillaThunderbird:

  - update to Thunderbird 17.0.3 (bnc#804248)

  * MFSA 2013-21/CVE-2013-0783 Miscellaneous memory safety
  hazards

  * MFSA 2013-24/CVE-2013-0773 (bmo#809652) Web content
  bypass of COW and SOW security wrappers

  * MFSA 2013-25/CVE-2013-0774 (bmo#827193) Privacy leak in
  JavaScript Workers

  * MFSA 2013-26/CVE-2013-0775 (bmo#831095) Use-after-free
  in nsImageLoadingContent

  * MFSA 2013-27/CVE-2013-0776 (bmo#796475) Phishing on
  HTTPS connection through malicious proxy

  * MFSA 2013-28/CVE-2013-0780/CVE-2013-0782
  Use-after-free, out of bounds read, and buffer overflow
  issues found using Address Sanitizer

  - update Enigmail to 1.5.1

  * The release fixes the regressions found in the past few
  weeks

  Changes in seamonkey:

  - update to SeaMonkey 2.16 (bnc#804248)

  * MFSA 2013-21/CVE-2013-0783/2013-0784 Miscellaneous
  memory safety hazards

  * MFSA 2013-22/CVE-2013-0772 (bmo#801366) Out-of-bounds
  read in image rendering

  * MFSA 2013-23/CVE-2013-0765 (bmo#830614) Wrapped WebIDL
  objects can be wrapped again

  * MFSA 2013-24/CVE- ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~19.0~2.62.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel-debuginfo", rpm:"MozillaThunderbird-devel-debuginfo~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chmsee", rpm:"chmsee~2.0~2.32.3", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chmsee-debuginfo", rpm:"chmsee-debuginfo~2.0~2.32.3", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chmsee-debugsource", rpm:"chmsee-debugsource~2.0~2.32.3", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.5.1+17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail-debuginfo", rpm:"enigmail-debuginfo~1.5.1+17.0.3~33.51.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js", rpm:"mozilla-js~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-debuginfo", rpm:"mozilla-js-debuginfo~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.16~2.53.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-buildsymbols", rpm:"xulrunner-buildsymbols~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debugsource", rpm:"xulrunner-debugsource~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel-debuginfo", rpm:"xulrunner-devel-debuginfo~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-32bit", rpm:"mozilla-js-32bit~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-debuginfo-32bit", rpm:"mozilla-js-debuginfo-32bit~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-32bit", rpm:"xulrunner-32bit~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo-32bit", rpm:"xulrunner-debuginfo-32bit~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-debuginfo-x86", rpm:"mozilla-js-debuginfo-x86~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-x86", rpm:"mozilla-js-x86~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo-x86", rpm:"xulrunner-debuginfo-x86~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-x86", rpm:"xulrunner-x86~17.0.3~2.57.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
