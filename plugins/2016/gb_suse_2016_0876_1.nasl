###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0876_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaThunderbird openSUSE-SU-2016:0876-1 (MozillaThunderbird)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851258");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-25 06:13:53 +0100 (Fri, 25 Mar 2016)");
  script_cve_id("CVE-2015-4477", "CVE-2015-7207", "CVE-2016-1952", "CVE-2016-1954",
                "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1960", "CVE-2016-1961",
                "CVE-2016-1962", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966",
                "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791",
                "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795",
                "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799",
                "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaThunderbird openSUSE-SU-2016:0876-1 (MozillaThunderbird)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MozillaThunderbird was updated to 38.7.0 to fix the following issues:

  * Update to Thunderbird 38.7.0 (boo#969894)

  * MFSA 2015-81/CVE-2015-4477 (bmo#1179484) Use-after-free in MediaStream
  playback

  * MFSA 2015-136/CVE-2015-7207 (bmo#1185256) Same-origin policy violation
  using performance.getEntries and history navigation

  * MFSA 2016-16/CVE-2016-1952 Miscellaneous memory safety hazards

  * MFSA 2016-17/CVE-2016-1954 (bmo#1243178) Local file overwriting and
  potential privilege escalation through CSP reports

  * MFSA 2016-20/CVE-2016-1957 (bmo#1227052) Memory leak in libstagefright
  when deleting an array during MP4 processing

  * MFSA 2016-21/CVE-2016-1958 (bmo#1228754) Displayed page address can be
  overridden

  * MFSA 2016-23/CVE-2016-1960/ZDI-CAN-3545 (bmo#1246014) Use-after-free
  in HTML5 string parser

  * MFSA 2016-24/CVE-2016-1961/ZDI-CAN-3574 (bmo#1249377) Use-after-free
  in SetBody

  * MFSA 2016-25/CVE-2016-1962 (bmo#1240760) Use-after-free when using
  multiple WebRTC data channels

  * MFSA 2016-27/CVE-2016-1964 (bmo#1243335) Use-after-free during XML
  transformations

  * MFSA 2016-28/CVE-2016-1965 (bmo#1245264) Addressbar spoofing though
  history navigation and Location protocol property

  * MFSA 2016-31/CVE-2016-1966 (bmo#1246054) Memory corruption with
  malicious NPAPI plugin

  * MFSA 2016-34/CVE-2016-1974 (bmo#1228103) Out-of-bounds read in HTML
  parser following a failed allocation

  * MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
  CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
  CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
  CVE-2016-2800/CVE-2016-2801/CVE-2016-2802 Font vulnerabilities in the
  Graphite 2 library");
  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~38.7.0~40.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~38.7.0~40.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~38.7.0~40.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~38.7.0~40.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~38.7.0~40.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~38.7.0~40.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~38.7.0~40.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
