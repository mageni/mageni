###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2209_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaThunderbird openSUSE-SU-2017:2209-1 (MozillaThunderbird)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851598");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-19 07:36:44 +0200 (Sat, 19 Aug 2017)");
  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7782", "CVE-2017-7784",
                "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7791",
                "CVE-2017-7792", "CVE-2017-7798", "CVE-2017-7800", "CVE-2017-7801",
                "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7804", "CVE-2017-7807");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaThunderbird openSUSE-SU-2017:2209-1 (MozillaThunderbird)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for MozillaThunderbird to version 52.3 fixes security issues
  and bugs.

  The following vulnerabilities were fixed:

  - CVE-2017-7798: XUL injection in the style editor in devtools

  - CVE-2017-7800: Use-after-free in WebSockets during disconnection

  - CVE-2017-7801: Use-after-free with marquee during window resizing

  - CVE-2017-7784: Use-after-free with image observers

  - CVE-2017-7802: Use-after-free resizing image elements

  - CVE-2017-7785: Buffer overflow manipulating ARIA attributes in DOM

  - CVE-2017-7786: Buffer overflow while painting non-displayable SVG

  - CVE-2017-7753: Out-of-bounds read with cached style data and
  pseudo-elements#

  - CVE-2017-7787: Same-origin policy bypass with iframes through page
  reloads

  - CVE-2017-7807: Domain hijacking through AppCache fallback

  - CVE-2017-7792: Buffer overflow viewing certificates with an extremely
  long OID

  - CVE-2017-7804: Memory protection bypass through WindowsDllDetourPatcher

  - CVE-2017-7791: Spoofing following page navigation with data: protocol
  and modal alerts

  - CVE-2017-7782: WindowsDllDetourPatcher allocates memory without DEP
  protections

  - CVE-2017-7803: CSP containing 'sandbox' improperly applied

  - CVE-2017-7779: Memory safety bugs fixed in Firefox 55 and Firefox ESR
  52.3

  The following bugs were fixed:

  - Unwanted inline images shown in rogue SPAM messages

  - Deleting message from the POP3 server not working when maildir storage
  was used

  - Message disposition flag (replied / forwarded) lost when reply or
  forwarded message was stored as draft and draft was sent later

  - Inline images not scaled to fit when printing

  - Selected text from another message sometimes included in a reply

  - No authorisation prompt displayed when inserting image into email body
  although image URL requires authentication

  - Large attachments taking a long time to open under some circumstances");
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

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.3.0~41.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.3.0~41.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.3.0~41.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.3.0~41.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.3.0~41.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.3.0~41.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.3.0~41.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.3.0~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.3.0~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.3.0~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.3.0~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.3.0~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.3.0~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.3.0~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
