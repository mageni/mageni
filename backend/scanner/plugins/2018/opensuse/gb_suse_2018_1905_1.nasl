###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1905_1.nasl 12912 2018-12-31 08:46:47Z asteins $
#
# SuSE Update for Mozilla openSUSE-SU-2018:1905-1 (Mozilla)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851814");
  script_version("$Revision: 12912 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-31 09:46:47 +0100 (Mon, 31 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-07-07 05:54:04 +0200 (Sat, 07 Jul 2018)");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363",
                "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12372",
                "CVE-2018-12373", "CVE-2018-12374", "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Mozilla openSUSE-SU-2018:1905-1 (Mozilla)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for Mozilla Thunderbird to version 52.9.0 fixes multiple
  issues.

  Security issues fixed, inherited from the Mozilla common code base (MFSA
  2018-16, bsc#1098998):

  - CVE-2018-12359: Buffer overflow using computed size of canvas element

  - CVE-2018-12360: Use-after-free when using focus()

  - CVE-2018-12362: Integer overflow in SSSE3 scaler

  - CVE-2018-12363: Use-after-free when appending DOM nodes

  - CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins

  - CVE-2018-12365: Compromised IPC child process can list local filenames

  - CVE-2018-12366: Invalid data handling during QCMS transformations

  - CVE-2018-5188: Memory safety bugs fixed in Thunderbird 52.9.0

  Security issues fixed that affect e-mail privacy and integrity (including
  EFAIL):

  - CVE-2018-12372: S/MIME and PGP decryption oracles can be built with HTML
  emails (bsc#1100082)

  - CVE-2018-12373: S/MIME plaintext can be leaked through HTML
  reply/forward (bsc#1100079)

  - CVE-2018-12374: Using form to exfiltrate encrypted mail part by pressing
  enter in form field (bsc#1100081)

  The following options are available for added security in certain
  scenarios:

  - Option for not decrypting subordinate message parts that otherwise might
  reveal decryted content to the attacker. Preference
  mailnews.p7m_subparts_external needs to be set to true for added
  security.

  The following upstream changes are included:

  - Thunderbird will now prompt to compact IMAP folders even if the account
  is online

  - Fix various problems when forwarding messages inline when using 'simple'
  HTML view

  The following tracked packaging changes are included:

  - correct requires and provides handling (boo#1076907)

  - reduce memory footprint with %ix86 at linking time via additional
  compiler flags (boo#1091376)

  - Build from upstream source archive and verify source signature
  (boo#1085780)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-701=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-701=1");
  script_tag(name:"affected", value:"Mozilla on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00006.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.9.0~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.9.0~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.9.0~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.9.0~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.9.0~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.9.0~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.9.0~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
