###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2710_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaThunderbird openSUSE-SU-2017:2710-1 (MozillaThunderbird)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851626");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-10-12 10:28:21 +0200 (Thu, 12 Oct 2017)");
  script_cve_id("CVE-2017-7793", "CVE-2017-7805", "CVE-2017-7810", "CVE-2017-7814",
                "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7823", "CVE-2017-7824",
                "CVE-2017-7825");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaThunderbird openSUSE-SU-2017:2710-1 (MozillaThunderbird)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Thunderbird was updated to 52.4.0 (boo#1060445)

  * new behavior was introduced for replies to mailing list posts:'When
  replying to a mailing list, reply will be sent to address in From
  header ignoring Reply-to header'. A new preference
  mail.override_list_reply_to allows to restore the previous behavior.

  * Under certain circumstances (image attachment and non-image
  attachment), attached images were shown truncated in messages stored
  in IMAP folders not synchronised for offline use.

  * IMAP UIDs   0x7FFFFFFF now handled properly Security fixes from Gecko
  52.4esr

  * CVE-2017-7793 (bmo#1371889) Use-after-free with Fetch API

  * CVE-2017-7818 (bmo#1363723) Use-after-free during ARIA array
  manipulation

  * CVE-2017-7819 (bmo#1380292) Use-after-free while resizing images in
  design mode

  * CVE-2017-7824 (bmo#1398381) Buffer overflow when drawing and
  validating elements with ANGLE

  * CVE-2017-7805 (bmo#1377618) (fixed via NSS requirement) Use-after-free
  in TLS 1.2 generating handshake hashes

  * CVE-2017-7814 (bmo#1376036) Blob and data URLs bypass phishing and
  malware protection warnings

  * CVE-2017-7825 (bmo#1393624, bmo#1390980) (OSX-only) OS X fonts render
  some Tibetan and Arabic unicode characters as spaces

  * CVE-2017-7823 (bmo#1396320) CSP sandbox directive did not create a
  unique origin

  * CVE-2017-7810 Memory safety bugs fixed in Firefox 56 and Firefox ESR
  52.4

  - Add alsa-devel BuildRequires: we care for ALSA support to be built and
  thus need to ensure we get the dependencies in place. In the past,
  alsa-devel was pulled in by accident: we buildrequire libgnome-devel.
  This required esound-devel and that in turn pulled in alsa-devel for us.
  libgnome is being fixed to no longer require esound-devel.");
  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.4.0~41.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.4.0~41.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.4.0~41.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.4.0~41.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.4.0~41.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.4.0~41.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.4.0~41.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.4.0~47.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.4.0~47.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.4.0~47.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.4.0~47.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.4.0~47.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.4.0~47.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.4.0~47.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
