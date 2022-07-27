###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for MozillaFirefox,MozillaThunderbird,seamonkey SUSE-SA:2011:037
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850171");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:58:04 +0200 (Wed, 07 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2980", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984", "CVE-2011-2985", "CVE-2011-2986", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2990", "CVE-2011-2991", "CVE-2011-2992", "CVE-2011-2993");
  script_name("SuSE Update for MozillaFirefox, MozillaThunderbird, seamonkey SUSE-SA:2011:037");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaThunderbird, seamonkey'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE11\.3)");
  script_tag(name:"impact", value:"remote code execution");
  script_tag(name:"affected", value:"MozillaFirefox, MozillaThunderbird, seamonkey on openSUSE 11.3, openSUSE 11.4");
  script_tag(name:"insight", value:"Mozilla released a round of security updates.

  Mozilla Firefox was updated to version 6 on openSUSE 11.4,
  Mozilla Firefox was updated to version 3.6.20 on openSUSE 11.3 and
  SUSE Linux Enterprise 10 and 11.
  Seamonkey was updated to 2.3 on openSUSE 11.3, 11.4
  Mozilla Thunderbird was updated to 3.1.2 on openSUSE 11.3, 11.4.
  Mozilla XULRunner was updated to 1.9.2.20.

  The updates bring new features, fix bugs and security issues.

  * Miscellaneous memory safety hazards:

  Mozilla identified and fixed several memory safety bugs in the
  browser engine used in Firefox 4, Firefox 5 and other Mozilla-based
  products. Some of these bugs showed evidence of memory corruption
  under certain circumstances, and we presume that with enough effort
  at least some of these could be exploited to run arbitrary code.

  Gary Kwong, Igor Bukanov, Nils and Bob Clary reported memory safety
  issues which affected Thunderbird 3.1. CVE-2011-2982

  Aral Yaman reported a WebGL crash which affected Firefox 4 and
  Firefox 5. CVE-2011-2989

  Vivekanand Bolajwar reported a JavaScript crash which affected
  Firefox 4 and Firefox 5. CVE-2011-2991

  Bert Hubert and Theo Snelleman of Fox-IT reported a crash in the
  OGG reader which affected Firefox 4 and Firefox 5. CVE-2011-2992

  Mozilla developers and community members Robert Kaiser, Jesse
  Ruderman, moz_bug_r_a4, Mardeg, Gary Kwong, Christoph Diehl, Martijn
  Wargers, Travis Emmitt, Bob Clary and Jonathan Watt reported memory
  safety issues which affected Firefox 4 and Firefox 5. CVE-2011-2985

  * Unsigned scripts can call script inside signed JAR

  Rafael Gieschke reported that unsigned JavaScript could call into
  script inside a signed JAR thereby inheriting the identity of the
  site that signed the JAR as well as any permissions that a user
  had granted the signed JAR. CVE-2011-2993

  * String crash using WebGL shaders

  Michael Jordon of Context IS reported that an overly long shader
  program could cause a buffer overrun and crash in a string class
  used to store the shader source code. CVE-2011-2988

  * Heap overflow in ANGLE library

  Michael Jordon of Context IS reported a potentially exploitable heap
  overf ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-30.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-33.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-32.html");

  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~6.0~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~6.0~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~6.0~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~6.0~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~6.0~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~6.0~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~3.1.12~0.11.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~3.1.12~0.11.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~3.1.12~0.11.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~3.1.12~0.11.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~3.1.12~0.11.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.1.2+3.1.12~0.11.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js192", rpm:"mozilla-js192~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.8.9~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.8.9~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-buildsymbols", rpm:"mozilla-xulrunner192-buildsymbols~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-devel", rpm:"mozilla-xulrunner192-devel~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common", rpm:"mozilla-xulrunner192-translations-common~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other", rpm:"mozilla-xulrunner192-translations-other~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.3~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.3~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.3~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.3~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.3~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.3~2.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js192-32bit", rpm:"mozilla-js192-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.8.9~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.12.11~1.3.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome-32bit", rpm:"mozilla-xulrunner192-gnome-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common-32bit", rpm:"mozilla-xulrunner192-translations-common-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other-32bit", rpm:"mozilla-xulrunner192-translations-other-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.6.20~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.6.20~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~3.6.20~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~3.6.20~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~3.1.12~0.15.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~3.1.12~0.15.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~3.1.12~0.15.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~3.1.12~0.15.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.1.2+3.1.12~0.15.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js192", rpm:"mozilla-js192~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.8.9~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.8.9~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-buildsymbols", rpm:"mozilla-xulrunner192-buildsymbols~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-devel", rpm:"mozilla-xulrunner192-devel~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common", rpm:"mozilla-xulrunner192-translations-common~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other", rpm:"mozilla-xulrunner192-translations-other~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.3~2.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.3~2.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.3~2.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.3~2.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.3~2.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.3~2.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js192-32bit", rpm:"mozilla-js192-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.8.9~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.12.11~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome-32bit", rpm:"mozilla-xulrunner192-gnome-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common-32bit", rpm:"mozilla-xulrunner192-translations-common-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other-32bit", rpm:"mozilla-xulrunner192-translations-other-32bit~1.9.2.20~1.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
