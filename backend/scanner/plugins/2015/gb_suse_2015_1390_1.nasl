###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1390_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaFirefox openSUSE-SU-2015:1390-1 (MozillaFirefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850668");
  script_version("$Revision: 12381 $");
  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4477",
                "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4481",
                "CVE-2015-4482", "CVE-2015-4483", "CVE-2015-4484", "CVE-2015-4485",
                "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489",
                "CVE-2015-4490", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4493",
                "CVE-2015-4495");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-08-15 05:00:45 +0200 (Sat, 15 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox openSUSE-SU-2015:1390-1 (MozillaFirefox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"- update to Firefox 40.0 (bnc#940806)

  * Added protection against unwanted software downloads

  * Suggested Tiles show sites of interest, based on categories from your
  recent browsing history

  * Hello allows adding a link to conversations to provide context
  on what the conversation will be about

  * New style for add-on manager based on the in-content preferences style

  * Improved scrolling, graphics, and video playback performance with off
  main thread compositing (GNU/Linux only)

  * Graphic blocklist mechanism improved: Firefox version ranges can be
  specified, limiting the number of devices blocked security fixes:

  * MFSA 2015-79/CVE-2015-4473/CVE-2015-4474 Miscellaneous memory safety
  hazards

  * MFSA 2015-80/CVE-2015-4475 (bmo#1175396) Out-of-bounds read with
  malformed MP3 file

  * MFSA 2015-81/CVE-2015-4477 (bmo#1179484) Use-after-free in MediaStream
  playback

  * MFSA 2015-82/CVE-2015-4478 (bmo#1105914) Redefinition of
  non-configurable JavaScript object properties

  * MFSA 2015-83/CVE-2015-4479/CVE-2015-4480/CVE-2015-4493 Overflow issues
  in libstagefright

  * MFSA 2015-84/CVE-2015-4481 (bmo1171518) Arbitrary file overwriting
  through Mozilla Maintenance Service with hard links (only affected
  Windows)

  * MFSA 2015-85/CVE-2015-4482 (bmo#1184500) Out-of-bounds write with
  Updater and malicious MAR file (does not affect openSUSE RPM packages
  which do not ship the updater)

  * MFSA 2015-86/CVE-2015-4483 (bmo#1148732) Feed protocol with POST
  bypasses mixed content protections

  * MFSA 2015-87/CVE-2015-4484 (bmo#1171540) Crash when using shared
  memory in JavaScript

  * MFSA 2015-88/CVE-2015-4491 (bmo#1184009) Heap overflow in gdk-pixbuf
  when scaling bitmap images

  * MFSA 2015-89/CVE-2015-4485/CVE-2015-4486 (bmo#1177948, bmo#1178148)
  Buffer overflows on Libvpx when decoding WebM video

  * MFSA 2015-90/CVE-2015-4487/CVE-2015-4488/CVE-2015-4489 Vulnerabilities
  found through code inspection

  * MFSA 2015-91/CVE-2015-4490 (bmo#1086999) Mozilla Content Security
  Policy allows for asterisk wildcards in violation of CSP specification

  * MFSA 2015-92/CVE-2015-4492 (bmo#1185820) Use-after-free in
  XMLHttpRequest with shared workers

  - added mozilla-no-stdcxx-check.patch

  - removed obsolete patches

  * mozilla-add-glibcxx_use_cxx11_abi.patch

  * firefox-multilocale-chrome.patch

  - rebased patches

  - requires version 40 of the branding package

  - removed browser/searchplugins/ location as it's not valid anymore

  - includes security update to Firefox 39.0.3 (bnc#940918)

  * MFSA 2015-78/CVE-2015-4495 (bmo#1179262, bmo#1178058) Same origin
  violation and local file stealing via PDF reader");
  script_tag(name:"affected", value:"MozillaFirefox on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-openSUSE-40", rpm:"MozillaFirefox-branding-openSUSE-40~2.3.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~40.0~82.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
