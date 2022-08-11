###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0733_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Firefox openSUSE-SU-2016:0733-1 (Firefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851234");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-13 06:16:27 +0100 (Sun, 13 Mar 2016)");
  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954",
                "CVE-2016-1955", "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1958",
                "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962",
                "CVE-2016-1963", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966",
                "CVE-2016-1967", "CVE-2016-1968", "CVE-2016-1970", "CVE-2016-1971",
                "CVE-2016-1972", "CVE-2016-1973", "CVE-2016-1974", "CVE-2016-1975",
                "CVE-2016-1976", "CVE-2016-1977", "CVE-2016-1979", "CVE-2016-2790",
                "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794",
                "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798",
                "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Firefox openSUSE-SU-2016:0733-1 (Firefox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for MozillaFirefox, mozilla-nspr, mozilla-nss fixes the
  following issues:

  MozillaFirefox was updated to Firefox 45.0 (boo#969894)

  * requires NSPR 4.12 / NSS 3.21.1

  * Instant browser tab sharing through Hello

  * Synced Tabs button in button bar

  * Tabs synced via Firefox Accounts from other devices are now shown in
  dropdown area of Awesome Bar when searching

  * Introduce a new preference (network.dns.blockDotOnion) to allow
  blocking .onion at the DNS level

  * Tab Groups (Panorama) feature removed

  * MFSA 2016-16/CVE-2016-1952/CVE-2016-1953 Miscellaneous memory safety
  hazards

  * MFSA 2016-17/CVE-2016-1954 (bmo#1243178) Local file overwriting and
  potential privilege escalation through CSP reports

  * MFSA 2016-18/CVE-2016-1955 (bmo#1208946) CSP reports fail to strip
  location information for embedded iframe pages

  * MFSA 2016-19/CVE-2016-1956 (bmo#1199923) Linux video memory DOS with
  Intel drivers

  * MFSA 2016-20/CVE-2016-1957 (bmo#1227052) Memory leak in
  libstagefright when deleting an array during MP4 processing

  * MFSA 2016-21/CVE-2016-1958 (bmo#1228754) Displayed page address can be
  overridden

  * MFSA 2016-22/CVE-2016-1959 (bmo#1234949) Service Worker Manager
  out-of-bounds read in Service Worker Manager

  * MFSA 2016-23/CVE-2016-1960/ZDI-CAN-3545 (bmo#1246014) Use-after-free
  in HTML5 string parser

  * MFSA 2016-24/CVE-2016-1961/ZDI-CAN-3574 (bmo#1249377) Use-after-free
  in SetBody

  * MFSA 2016-25/CVE-2016-1962 (bmo#1240760) Use-after-free when using
  multiple WebRTC data channels

  * MFSA 2016-26/CVE-2016-1963 (bmo#1238440) Memory corruption when
  modifying a file being read by FileReader

  * MFSA 2016-27/CVE-2016-1964 (bmo#1243335) Use-after-free during XML
  transformations

  * MFSA 2016-28/CVE-2016-1965 (bmo#1245264) Addressbar spoofing though
  history navigation and Location protocol property

  * MFSA 2016-29/CVE-2016-1967 (bmo#1246956) Same-origin policy violation
  using performance.getEntries and history navigation with session
  restore

  * MFSA 2016-30/CVE-2016-1968 (bmo#1246742) Buffer overflow in Brotli
  decompression

  * MFSA 2016-31/CVE-2016-1966 (bmo#1246054) Memory corruption with
  malicious NPAPI plugin

  * MFSA 2016-32/CVE-2016-1970/CVE-2016-1971/CVE-2016-1975/
  CVE-2016-1976/CVE-2016-1972 WebRTC and LibVPX vulnerabilities found
  through code inspection

  * MFSA 2016-33/CVE-2016-1973 (bmo#1219339) Use-after-free in
  GetStaticInstance in WebRTC

  * MFSA 2016-34/CVE-2016-1974 (bmo#1228103) Out-of-bounds read in HTML
  parser following a failed allocation

  * MFSA 2016-35/CVE-2016-1950 (bmo#1245528) Buffer overflow  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"Firefox on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~45.0~109.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.12~34.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.12~34.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.12~34.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.12~34.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.12~34.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.12~34.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.21.1~74.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
