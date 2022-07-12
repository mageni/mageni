###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_1633_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Mozilla Suite openSUSE-SU-2013:1633-1 (Mozilla Suite)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850541");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:42 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-1705", "CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725",
                "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736",
                "CVE-2013-1737", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592",
                "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597",
                "CVE-2013-5598", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601",
                "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for Mozilla Suite openSUSE-SU-2013:1633-1 (Mozilla Suite)");
  script_tag(name:"affected", value:"Mozilla Suite on openSUSE 12.2");
  script_tag(name:"insight", value:"MozillaFirefox was updated to Firefox 25.0.
  MozillaThunderbird was updated to Thunderbird 24.1.0.
  Mozilla XULRunner was updated to 17.0.10esr. Mozilla NSPR
  was updated to 4.10.1.

  Changes in MozillaFirefox:

  * requires NSS 3.15.2 or above

  * MFSA 2013-93/CVE-2013-5590/CVE-2013-5591/CVE-2013-5592
  Miscellaneous memory safety hazards

  * MFSA 2013-94/CVE-2013-5593 (bmo#868327) Spoofing
  addressbar through SELECT element

  * MFSA 2013-95/CVE-2013-5604 (bmo#914017) Access
  violation with XSLT and uninitialized data

  * MFSA 2013-96/CVE-2013-5595 (bmo#916580) Improperly
  initialized memory and overflows in some JavaScript
  functions

  * MFSA 2013-97/CVE-2013-5596 (bmo#910881) Writing to
  cycle collected object during image decoding

  * MFSA 2013-98/CVE-2013-5597 (bmo#918864) Use-after-free
  when updating offline cache

  * MFSA 2013-99/CVE-2013-5598 (bmo#920515) Security bypass
  of PDF.js checks using iframes

  * MFSA 2013-100/CVE-2013-5599/CVE-2013-5600/CVE-2013-5601
  (bmo#915210, bmo#915576, bmo#916685) Miscellaneous
  use-after-free issues found through ASAN fuzzing

  * MFSA 2013-101/CVE-2013-5602 (bmo#897678) Memory
  corruption in workers

  * MFSA 2013-102/CVE-2013-5603 (bmo#916404) Use-after-free
  in HTML document templates

  Changes in MozillaThunderbird:

  * requires NSS 3.15.2 or above

  * MFSA 2013-93/CVE-2013-5590/CVE-2013-5591/CVE-2013-5592
  Miscellaneous memory safety hazards

  * MFSA 2013-94/CVE-2013-5593 (bmo#868327) Spoofing
  addressbar through SELECT element

  * MFSA 2013-95/CVE-2013-5604 (bmo#914017) Access
  violation with XSLT and uninitialized data

  * MFSA 2013-96/CVE-2013-5595 (bmo#916580) Improperly
  initialized memory and overflows in some JavaScript
  functions

  * MFSA 2013-97/CVE-2013-5596 (bmo#910881) Writing to
  cycle collected object during image decoding

  * MFSA 2013-98/CVE-2013-5597 (bmo#918864) Use-after-free
  when updating offline cache

  * MFSA 2013-100/CVE-2013-5599/CVE-2013-5600/CVE-2013-5601
  (bmo#915210, bmo#915576, bmo#916685) Miscellaneous
  use-after-free issues found through ASAN fuzzing

  * MFSA 2013-101/CVE-2013-5602 (bmo#897678) Memory
  corruption in workers

  * MFSA 2013-102/CVE-2013-5603 (bmo#916404) Use-after-free
  in HTML document templates

  - update to Thunderbird 24.0.1

  * fqdn for smtp server name was not accepted (bmo#913785)

  * fixed crash in PL_strncasecmp (bmo#917955)

  - update Enigmail to 1.6

  * The passphrase timeout configuration in Enigmail is now
  read and written from/to gpg-agent.

  * New dialog to change the expiry date of keys

  * New function to search for the OpenPGP keys of all
  Add ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Suite'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~25.0~2.63.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.6.0+24.1.0~49.59.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js", rpm:"mozilla-js~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-debuginfo", rpm:"mozilla-js-debuginfo~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.1~1.20.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.10.1~1.20.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.10.1~1.20.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.10.1~1.20.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-buildsymbols", rpm:"xulrunner-buildsymbols~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debugsource", rpm:"xulrunner-debugsource~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel-debuginfo", rpm:"xulrunner-devel-debuginfo~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-32bit", rpm:"mozilla-js-32bit~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-debuginfo-32bit", rpm:"mozilla-js-debuginfo-32bit~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.1~1.20.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.10.1~1.20.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-32bit", rpm:"xulrunner-32bit~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo-32bit", rpm:"xulrunner-debuginfo-32bit~17.0.10~2.56.2", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
