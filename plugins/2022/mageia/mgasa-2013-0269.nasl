# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0269");
  script_cve_id("CVE-2013-2126", "CVE-2013-2127", "CVE-2013-4132", "CVE-2013-4133");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 14:14:00 +0000 (Tue, 17 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2013-0269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0269");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0269.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10600");
  script_xref(name:"URL", value:"https://bugs.kde.org/buglist.cgi?query_format=advanced&short_desc_type=allwordssubstr&short_desc=&long_desc_type=substring&long_desc=&bug_file_loc_type=allwordssubstr&bug_file_loc=&keywords_type=allwords&keywords=&bug_status=RESOLVED&bug_status=VERIFIED&bug_status=CLOSED&emailtype1=substring&email1=&emailassigned_to2=1&emailreporter2=1&emailcc2=1&emailtype2=substring&email2=&bugidtype=include&bug_id=&votes=&chfieldfrom=2013-06-01&chfieldto=Now&chfield=cf_versionfixedin&chfieldvalue=4.10.5&cmdtype=doit&order=Bug+Number&field0-0-0=noop&type0-0-0=noop&value0-0-0=");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'analitza, ark, blinken, bomber, bovo, cantor, dragon, ffmpegthumbs, filelight, granatier, gwenview, jovie, juk, kaccessible, kajongg, kalgebra, kalzium, kamera, kanagram, kapman, kate, katomic, kblackbox, kblocks, kbounce, kbreakout, kbruch, kcalc, kcharselect, kcolorchooser, kde-base-artwork, kde-l10n, kde-wallpapers, kde4-audiocd, kdeadmin4, kdeartwork4, kdebase4, kdebase4-runtime, kdebase4-workspace, kdegraphics-mobipocket, kdegraphics-strigi-analyzer, kdegraphics-thumbnailers, kdelibs4, kdenetwork4, kdepim4, kdepim4-runtime, kdepimlibs4, kdeplasma-addons, kdesdk4, kdetoys4, kdewebdev4, kdf, kdiamond, kfloppy, kfourinline, kgamma, kgeography, kgoldrunner, kgpg, khangman, kig, kigo, killbots, kimono, kiriki, kiten, kjumpingcube, klettres, klickety, klines, kmag, kmahjongg, kmines, kmix, kmousetool, kmouth, kmplot, knavalbattle, knetwalk, kolf, kollision, kolourpaint, konquest, konsole, korundum, kpat, kremotecontrol, kreversi, kross-interpreters, kruler, ksaneplugin, kscd, kshisen, ksirk, ksnakeduel, ksnapshot, kspaceduel, ksquares, kstars, ksudoku, ktimer, ktouch, ktuberling, kturtle, kubrick, kwallet, kwordquiz, libkactivities, libkcddb, libkcompactdisc, libkdcraw, libkdeedu, libkdegames, libkexiv2, libkipi, libkmahjongg, libksane, lskat, marble, mplayerthumbs, nepomuk-core, nepomuk-widgets, okular, oxygen-icon-theme, pairs, palapeli, parley, perl-kde4, perl-qt4, picmi, print-manager, python-kde4, qyoto, rocs, ruby-qt4, smokegen, smokekde, smokeqt, step, superkaramba, svgpart, sweeper, task-kde4' package(s) announced via the MGASA-2013-0269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the last stable version of KDE for the 4.10.x
branch. Some of the new packages fixes additional issues open on our
tracker :
- A memory leak in kde-workspace (kde #314919 & mga #7953)
- A memory leak in kmix ( mga #10702 & kde #309464 )
- A packaging issue affecting kdebase4-runtime (mga #10387) & another
 affecting kdegraphics-thumbnailers (mga #10388)
- A crash of akonadi davgroupware resource ( mga #10396)
- Several security issues affecting libraw & so libkdcraw
 ( CVE-2013-2126, CVE-2013-2127,
- Several security fixes affecting kdebase4-workspace
 ( CVE-2013-4132 & CVE-2013-4133 )
See the referenced buglist for the complete list of fixes.");

  script_tag(name:"affected", value:"'analitza, ark, blinken, bomber, bovo, cantor, dragon, ffmpegthumbs, filelight, granatier, gwenview, jovie, juk, kaccessible, kajongg, kalgebra, kalzium, kamera, kanagram, kapman, kate, katomic, kblackbox, kblocks, kbounce, kbreakout, kbruch, kcalc, kcharselect, kcolorchooser, kde-base-artwork, kde-l10n, kde-wallpapers, kde4-audiocd, kdeadmin4, kdeartwork4, kdebase4, kdebase4-runtime, kdebase4-workspace, kdegraphics-mobipocket, kdegraphics-strigi-analyzer, kdegraphics-thumbnailers, kdelibs4, kdenetwork4, kdepim4, kdepim4-runtime, kdepimlibs4, kdeplasma-addons, kdesdk4, kdetoys4, kdewebdev4, kdf, kdiamond, kfloppy, kfourinline, kgamma, kgeography, kgoldrunner, kgpg, khangman, kig, kigo, killbots, kimono, kiriki, kiten, kjumpingcube, klettres, klickety, klines, kmag, kmahjongg, kmines, kmix, kmousetool, kmouth, kmplot, knavalbattle, knetwalk, kolf, kollision, kolourpaint, konquest, konsole, korundum, kpat, kremotecontrol, kreversi, kross-interpreters, kruler, ksaneplugin, kscd, kshisen, ksirk, ksnakeduel, ksnapshot, kspaceduel, ksquares, kstars, ksudoku, ktimer, ktouch, ktuberling, kturtle, kubrick, kwallet, kwordquiz, libkactivities, libkcddb, libkcompactdisc, libkdcraw, libkdeedu, libkdegames, libkexiv2, libkipi, libkmahjongg, libksane, lskat, marble, mplayerthumbs, nepomuk-core, nepomuk-widgets, okular, oxygen-icon-theme, pairs, palapeli, parley, perl-kde4, perl-qt4, picmi, print-manager, python-kde4, qyoto, rocs, ruby-qt4, smokegen, smokekde, smokeqt, step, superkaramba, svgpart, sweeper, task-kde4' package(s) on Mageia 3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"akonadi-kde", rpm:"akonadi-kde~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"akonadiconsole", rpm:"akonadiconsole~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"akregator", rpm:"akregator~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"akregator-handbook", rpm:"akregator-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"amor", rpm:"amor~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"analitza", rpm:"analitza~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"analitza-data", rpm:"analitza-data~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ark", rpm:"ark~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ark-devel", rpm:"ark-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ark-handbook", rpm:"ark-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blinken", rpm:"blinken~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blinken-handbook", rpm:"blinken-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blogilo", rpm:"blogilo~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blogilo-handbook", rpm:"blogilo-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bomber", rpm:"bomber~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bomber-handbook", rpm:"bomber-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bovo", rpm:"bovo~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bovo-handbook", rpm:"bovo-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calgebra", rpm:"calgebra~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cantor", rpm:"cantor~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cantor-devel", rpm:"cantor-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cantor-handbook", rpm:"cantor-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cervisia", rpm:"cervisia~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dolphin", rpm:"dolphin~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dolphin-handbook", rpm:"dolphin-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dragon", rpm:"dragon~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dragon-handbook", rpm:"dragon-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpegthumbs", rpm:"ffmpegthumbs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"filelight", rpm:"filelight~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"filelight-handbook", rpm:"filelight-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fonts-ttf-kanjistrokeorders", rpm:"fonts-ttf-kanjistrokeorders~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"granatier", rpm:"granatier~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"granatier-handbook", rpm:"granatier-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gwenview", rpm:"gwenview~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gwenview-devel", rpm:"gwenview-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gwenview-handbook", rpm:"gwenview-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jovie", rpm:"jovie~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jovie-devel", rpm:"jovie-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jovie-handbook", rpm:"jovie-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"juk", rpm:"juk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"juk-handbook", rpm:"juk-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kaccessible", rpm:"kaccessible~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kactivitymanagerd", rpm:"kactivitymanagerd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kactivitymanagerd-nepomuk-plugin", rpm:"kactivitymanagerd-nepomuk-plugin~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kaddressbook", rpm:"kaddressbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kaddressbook-handbook", rpm:"kaddressbook-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kajongg", rpm:"kajongg~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kajongg-handbook", rpm:"kajongg-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalarm", rpm:"kalarm~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalarm-handbook", rpm:"kalarm-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalgebra", rpm:"kalgebra~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalgebra-handbook", rpm:"kalgebra-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalzium", rpm:"kalzium~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalzium-devel", rpm:"kalzium-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalzium-handbook", rpm:"kalzium-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kamera", rpm:"kamera~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kamera-handbook", rpm:"kamera-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kanagram", rpm:"kanagram~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kanagram-devel", rpm:"kanagram-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kanagram-handbook", rpm:"kanagram-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kapman", rpm:"kapman~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kapman-handbook", rpm:"kapman-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kapptemplate", rpm:"kapptemplate~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kate", rpm:"kate~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kate-devel", rpm:"kate-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kate-handbook", rpm:"kate-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kate-plugin-pate", rpm:"kate-plugin-pate~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"katepart", rpm:"katepart~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"katomic", rpm:"katomic~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"katomic-handbook", rpm:"katomic-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kblackbox", rpm:"kblackbox~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kblackbox-handbook", rpm:"kblackbox-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kblocks", rpm:"kblocks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kblocks-handbook", rpm:"kblocks-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbounce", rpm:"kbounce~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbounce-handbook", rpm:"kbounce-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbreakout", rpm:"kbreakout~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbreakout-handbook", rpm:"kbreakout-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbruch", rpm:"kbruch~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbruch-handbook", rpm:"kbruch-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcachegrind", rpm:"kcachegrind~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcalc", rpm:"kcalc~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcalc-handbook", rpm:"kcalc-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcharselect", rpm:"kcharselect~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcharselect-handbook", rpm:"kcharselect-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcm_cddb", rpm:"kcm_cddb~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcm_cddb-handbook", rpm:"kcm_cddb-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcolorchooser", rpm:"kcolorchooser~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcron", rpm:"kcron~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcron-handbook", rpm:"kcron-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-base-artwork", rpm:"kde-base-artwork~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n", rpm:"kde-l10n~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ar", rpm:"kde-l10n-ar~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-bg", rpm:"kde-l10n-bg~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-bs", rpm:"kde-l10n-bs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ca", rpm:"kde-l10n-ca~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ca-valencia", rpm:"kde-l10n-ca-valencia~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-cs", rpm:"kde-l10n-cs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-da", rpm:"kde-l10n-da~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-de", rpm:"kde-l10n-de~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-el", rpm:"kde-l10n-el~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-en_GB", rpm:"kde-l10n-en_GB~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-en_US", rpm:"kde-l10n-en_US~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-es", rpm:"kde-l10n-es~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-et", rpm:"kde-l10n-et~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-eu", rpm:"kde-l10n-eu~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-fa", rpm:"kde-l10n-fa~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-fi", rpm:"kde-l10n-fi~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-fr", rpm:"kde-l10n-fr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ga", rpm:"kde-l10n-ga~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-gl", rpm:"kde-l10n-gl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-ca", rpm:"kde-l10n-handbooks-ca~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-cs", rpm:"kde-l10n-handbooks-cs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-da", rpm:"kde-l10n-handbooks-da~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-de", rpm:"kde-l10n-handbooks-de~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-el", rpm:"kde-l10n-handbooks-el~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-en_GB", rpm:"kde-l10n-handbooks-en_GB~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-es", rpm:"kde-l10n-handbooks-es~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-et", rpm:"kde-l10n-handbooks-et~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-eu", rpm:"kde-l10n-handbooks-eu~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-fr", rpm:"kde-l10n-handbooks-fr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-gl", rpm:"kde-l10n-handbooks-gl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-he", rpm:"kde-l10n-handbooks-he~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-hu", rpm:"kde-l10n-handbooks-hu~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-it", rpm:"kde-l10n-handbooks-it~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-ja", rpm:"kde-l10n-handbooks-ja~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-ko", rpm:"kde-l10n-handbooks-ko~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-lt", rpm:"kde-l10n-handbooks-lt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-nb", rpm:"kde-l10n-handbooks-nb~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-nds", rpm:"kde-l10n-handbooks-nds~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-nl", rpm:"kde-l10n-handbooks-nl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-nn", rpm:"kde-l10n-handbooks-nn~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-pl", rpm:"kde-l10n-handbooks-pl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-pt", rpm:"kde-l10n-handbooks-pt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-pt_BR", rpm:"kde-l10n-handbooks-pt_BR~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-ro", rpm:"kde-l10n-handbooks-ro~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-ru", rpm:"kde-l10n-handbooks-ru~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-sl", rpm:"kde-l10n-handbooks-sl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-sr", rpm:"kde-l10n-handbooks-sr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-sv", rpm:"kde-l10n-handbooks-sv~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-tr", rpm:"kde-l10n-handbooks-tr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-uk", rpm:"kde-l10n-handbooks-uk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-wa", rpm:"kde-l10n-handbooks-wa~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-zh_CN", rpm:"kde-l10n-handbooks-zh_CN~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-handbooks-zh_TW", rpm:"kde-l10n-handbooks-zh_TW~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-he", rpm:"kde-l10n-he~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-hi", rpm:"kde-l10n-hi~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-hr", rpm:"kde-l10n-hr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-hu", rpm:"kde-l10n-hu~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ia", rpm:"kde-l10n-ia~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-is", rpm:"kde-l10n-is~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-it", rpm:"kde-l10n-it~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ja", rpm:"kde-l10n-ja~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-kk", rpm:"kde-l10n-kk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-km", rpm:"kde-l10n-km~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ko", rpm:"kde-l10n-ko~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-lt", rpm:"kde-l10n-lt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-lv", rpm:"kde-l10n-lv~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-mr", rpm:"kde-l10n-mr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-nb", rpm:"kde-l10n-nb~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-nds", rpm:"kde-l10n-nds~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-nl", rpm:"kde-l10n-nl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-nn", rpm:"kde-l10n-nn~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-pa", rpm:"kde-l10n-pa~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-pl", rpm:"kde-l10n-pl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-pt", rpm:"kde-l10n-pt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-pt_BR", rpm:"kde-l10n-pt_BR~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ro", rpm:"kde-l10n-ro~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ru", rpm:"kde-l10n-ru~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-si", rpm:"kde-l10n-si~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-sk", rpm:"kde-l10n-sk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-sl", rpm:"kde-l10n-sl~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-sr", rpm:"kde-l10n-sr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-sv", rpm:"kde-l10n-sv~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-tg", rpm:"kde-l10n-tg~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-th", rpm:"kde-l10n-th~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-tr", rpm:"kde-l10n-tr~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-ug", rpm:"kde-l10n-ug~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-uk", rpm:"kde-l10n-uk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-vi", rpm:"kde-l10n-vi~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-wa", rpm:"kde-l10n-wa~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-zh_CN", rpm:"kde-l10n-zh_CN~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-l10n-zh_TW", rpm:"kde-l10n-zh_TW~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde-wallpapers", rpm:"kde-wallpapers~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-audiocd", rpm:"kde4-audiocd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-audiocd-devel", rpm:"kde4-audiocd-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-audiocd-handbook", rpm:"kde4-audiocd-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-filesharing", rpm:"kde4-filesharing~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-nsplugins", rpm:"kde4-nsplugins~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeaccessibility4", rpm:"kdeaccessibility4~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeadmin4", rpm:"kdeadmin4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeadmin4-handbooks", rpm:"kdeadmin4-handbooks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4", rpm:"kdeartwork4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4-color-schemes", rpm:"kdeartwork4-color-schemes~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4-emoticons", rpm:"kdeartwork4-emoticons~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4-icons-theme-nuvola", rpm:"kdeartwork4-icons-theme-nuvola~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4-kscreensaver", rpm:"kdeartwork4-kscreensaver~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4-sounds", rpm:"kdeartwork4-sounds~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4-styles", rpm:"kdeartwork4-styles~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeartwork4-wallpapers", rpm:"kdeartwork4-wallpapers~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4", rpm:"kdebase4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-common", rpm:"kdebase4-common~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-devel", rpm:"kdebase4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-handbooks", rpm:"kdebase4-handbooks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-runtime", rpm:"kdebase4-runtime~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-runtime-devel", rpm:"kdebase4-runtime-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-runtime-handbook", rpm:"kdebase4-runtime-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace", rpm:"kdebase4-workspace~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace-devel", rpm:"kdebase4-workspace-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace-handbooks", rpm:"kdebase4-workspace-handbooks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace-plasma-config", rpm:"kdebase4-workspace-plasma-config~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kded_randrmonitor", rpm:"kded_randrmonitor~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeedu4", rpm:"kdeedu4~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdegames4", rpm:"kdegames4~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdegraphics-mobipocket", rpm:"kdegraphics-mobipocket~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdegraphics-strigi-analyzer", rpm:"kdegraphics-strigi-analyzer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdegraphics-thumbnailers", rpm:"kdegraphics-thumbnailers~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdegraphics4", rpm:"kdegraphics4~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-devel", rpm:"kdelibs4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-handbooks", rpm:"kdelibs4-handbooks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdenetwork-strigi-analyzers", rpm:"kdenetwork-strigi-analyzers~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdenetwork4", rpm:"kdenetwork4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdenetwork4-devel", rpm:"kdenetwork4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepasswd", rpm:"kdepasswd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepasswd-handbook", rpm:"kdepasswd-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4", rpm:"kdepim4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-core", rpm:"kdepim4-core~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-devel", rpm:"kdepim4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-kresources", rpm:"kdepim4-kresources~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-runtime", rpm:"kdepim4-runtime~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-runtime-devel", rpm:"kdepim4-runtime-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepimlibs4", rpm:"kdepimlibs4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepimlibs4-core", rpm:"kdepimlibs4-core~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepimlibs4-devel", rpm:"kdepimlibs4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepimlibs4-handbooks", rpm:"kdepimlibs4-handbooks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeplasma-addons", rpm:"kdeplasma-addons~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeplasma-addons-devel", rpm:"kdeplasma-addons-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdesdk4", rpm:"kdesdk4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdesdk4-core", rpm:"kdesdk4-core~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdesdk4-devel", rpm:"kdesdk4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdesdk4-po2xml", rpm:"kdesdk4-po2xml~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdesdk4-scripts", rpm:"kdesdk4-scripts~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdesdk4-strigi-analyzer", rpm:"kdesdk4-strigi-analyzer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdetoys4", rpm:"kdetoys4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeutils4", rpm:"kdeutils4~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdewebdev4", rpm:"kdewebdev4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdewebdev4-devel", rpm:"kdewebdev4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdf", rpm:"kdf~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdf-handbook", rpm:"kdf-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdialog", rpm:"kdialog~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdiamond", rpm:"kdiamond~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdiamond-handbook", rpm:"kdiamond-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdm", rpm:"kdm~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdm-handbook", rpm:"kdm-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdnssd", rpm:"kdnssd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keditbookmarks", rpm:"keditbookmarks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfilereplace", rpm:"kfilereplace~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfilereplace-handbook", rpm:"kfilereplace-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfind", rpm:"kfind~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfind-handbook", rpm:"kfind-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfloppy", rpm:"kfloppy~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfloppy-handbook", rpm:"kfloppy-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfourinline", rpm:"kfourinline~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kfourinline-handbook", rpm:"kfourinline-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgamma", rpm:"kgamma~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgamma-handbook", rpm:"kgamma-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgeography", rpm:"kgeography~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgeography-handbook", rpm:"kgeography-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kget", rpm:"kget~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kget-handbook", rpm:"kget-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgoldrunner", rpm:"kgoldrunner~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgoldrunner-handbook", rpm:"kgoldrunner-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgpg", rpm:"kgpg~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgpg-handbook", rpm:"kgpg-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"khangman", rpm:"khangman~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"khangman-devel", rpm:"khangman-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"khangman-handbook", rpm:"khangman-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kig", rpm:"kig~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kig-handbook", rpm:"kig-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kigo", rpm:"kigo~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kigo-handbook", rpm:"kigo-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"killbots", rpm:"killbots~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"killbots-handbook", rpm:"killbots-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kimagemapeditor", rpm:"kimagemapeditor~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kimagemapeditor-handbook", rpm:"kimagemapeditor-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kimono", rpm:"kimono~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kincidenceeditor", rpm:"kincidenceeditor~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kinfocenter", rpm:"kinfocenter~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kinfocenter-handbook", rpm:"kinfocenter-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kio4-imap", rpm:"kio4-imap~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kio4-ldap", rpm:"kio4-ldap~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kio4-mbox", rpm:"kio4-mbox~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kio4-nntp", rpm:"kio4-nntp~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kio4-pop3", rpm:"kio4-pop3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kio4-sieve", rpm:"kio4-sieve~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kio4-smtp", rpm:"kio4-smtp~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kipi-common", rpm:"kipi-common~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kipi-plugin-kxmlhelloword", rpm:"kipi-plugin-kxmlhelloword~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kiriki", rpm:"kiriki~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kiriki-handbook", rpm:"kiriki-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kiten", rpm:"kiten~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kiten-devel", rpm:"kiten-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kiten-handbook", rpm:"kiten-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kjots", rpm:"kjots~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kjots-handbook", rpm:"kjots-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kjumpingcube", rpm:"kjumpingcube~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kjumpingcube-handbook", rpm:"kjumpingcube-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kleopatra", rpm:"kleopatra~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kleopatra-handbook", rpm:"kleopatra-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klettres", rpm:"klettres~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klettres-handbook", rpm:"klettres-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klickety", rpm:"klickety~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klickety-handbook", rpm:"klickety-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klines", rpm:"klines~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klines-handbook", rpm:"klines-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klinkstatus", rpm:"klinkstatus~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"klinkstatus-handbook", rpm:"klinkstatus-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmag", rpm:"kmag~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmag-handbook", rpm:"kmag-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmahjongg", rpm:"kmahjongg~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmahjongg-handbook", rpm:"kmahjongg-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmahjongglib", rpm:"kmahjongglib~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmail", rpm:"kmail~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmail-handbook", rpm:"kmail-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmailcvt", rpm:"kmailcvt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmines", rpm:"kmines~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmines-handbook", rpm:"kmines-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmix", rpm:"kmix~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmix-handbook", rpm:"kmix-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmousetool", rpm:"kmousetool~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmousetool-handbook", rpm:"kmousetool-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmouth", rpm:"kmouth~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmouth-handbook", rpm:"kmouth-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmplot", rpm:"kmplot~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmtrace", rpm:"kmtrace~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knavalbattle", rpm:"knavalbattle~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knavalbattle-handbook", rpm:"knavalbattle-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knetwalk", rpm:"knetwalk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knetwalk-handbook", rpm:"knetwalk-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knode", rpm:"knode~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knode-handbook", rpm:"knode-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knotes", rpm:"knotes~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knotes-handbook", rpm:"knotes-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kolf", rpm:"kolf~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kolf-handbook", rpm:"kolf-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kollision", rpm:"kollision~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kollision-handbook", rpm:"kollision-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kolourpaint", rpm:"kolourpaint~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kolourpaint-devel", rpm:"kolourpaint-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kolourpaint-handbook", rpm:"kolourpaint-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kommander", rpm:"kommander~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kompare", rpm:"kompare~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"konq-plugins", rpm:"konq-plugins~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"konqueror", rpm:"konqueror~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"konqueror-handbook", rpm:"konqueror-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"konquest", rpm:"konquest~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"konquest-handbook", rpm:"konquest-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"konsole", rpm:"konsole~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"konsole-doc", rpm:"konsole-doc~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kontact", rpm:"kontact~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kontact-handbook", rpm:"kontact-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kopete", rpm:"kopete~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kopete-handbook", rpm:"kopete-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kopete-latex", rpm:"kopete-latex~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"korganizer", rpm:"korganizer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"korganizer-handbook", rpm:"korganizer-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"korundum", rpm:"korundum~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"korundum-devel", rpm:"korundum-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kpat", rpm:"kpat~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kpat-handbook", rpm:"kpat-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kppp", rpm:"kppp~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kppp-handbook", rpm:"kppp-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kppp-provider", rpm:"kppp-provider~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krdc", rpm:"krdc~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krdc-handbook", rpm:"krdc-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kremotecontrol", rpm:"kremotecontrol~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kremotecontrol-devel", rpm:"kremotecontrol-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kremotecontrol-handbook", rpm:"kremotecontrol-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kreversi", rpm:"kreversi~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kreversi-handbook", rpm:"kreversi-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krfb", rpm:"krfb~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krfb-handbook", rpm:"krfb-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kross-interpreters", rpm:"kross-interpreters~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kross-interpreters-java", rpm:"kross-interpreters-java~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kross-interpreters-python", rpm:"kross-interpreters-python~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kross-interpreters-ruby", rpm:"kross-interpreters-ruby~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kruler", rpm:"kruler~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kruler-handbook", rpm:"kruler-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksaneplugin", rpm:"ksaneplugin~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kscd", rpm:"kscd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksendemail", rpm:"ksendemail~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kshisen", rpm:"kshisen~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kshisen-handbook", rpm:"kshisen-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksirk", rpm:"ksirk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksirk-handbook", rpm:"ksirk-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksnakeduel", rpm:"ksnakeduel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksnapshot", rpm:"ksnapshot~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksnapshot-handbook", rpm:"ksnapshot-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kspaceduel", rpm:"kspaceduel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kspaceduel-handbook", rpm:"kspaceduel-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksquares", rpm:"ksquares~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksquares-handbook", rpm:"ksquares-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kstars", rpm:"kstars~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kstars-handbook", rpm:"kstars-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksudoku", rpm:"ksudoku~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksudoku-handbook", rpm:"ksudoku-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksystemlog", rpm:"ksystemlog~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksystemlog-handbook", rpm:"ksystemlog-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kteatime", rpm:"kteatime~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktexteditor", rpm:"ktexteditor~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktimer", rpm:"ktimer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktimer-handbook", rpm:"ktimer-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktimetracker", rpm:"ktimetracker~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktimetracker-handbook", rpm:"ktimetracker-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktnef", rpm:"ktnef~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktnef-handbook", rpm:"ktnef-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktouch", rpm:"ktouch~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktouch-handbook", rpm:"ktouch-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktron", rpm:"ktron~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktron-handbook", rpm:"ktron-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktuberling", rpm:"ktuberling~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktuberling-handbook", rpm:"ktuberling-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kturtle", rpm:"kturtle~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktux", rpm:"ktux~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubrick", rpm:"kubrick~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubrick-handbook", rpm:"kubrick-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kuiviewer", rpm:"kuiviewer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kuser", rpm:"kuser~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kuser-handbook", rpm:"kuser-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwallet", rpm:"kwallet~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwallet-daemon", rpm:"kwallet-daemon~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwallet-handbook", rpm:"kwallet-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwordquiz", rpm:"kwordquiz~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwrite", rpm:"kwrite~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwrite-handbook", rpm:"kwrite-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxmlkipicmd", rpm:"kxmlkipicmd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-calendar4", rpm:"lib64akonadi-calendar4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-contact4", rpm:"lib64akonadi-contact4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-filestore4", rpm:"lib64akonadi-filestore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-kabc4", rpm:"lib64akonadi-kabc4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-kcal4", rpm:"lib64akonadi-kcal4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-kde4", rpm:"lib64akonadi-kde4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-kmime4", rpm:"lib64akonadi-kmime4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-next4", rpm:"lib64akonadi-next4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-notes4", rpm:"lib64akonadi-notes4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-xml4", rpm:"lib64akonadi-xml4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi_socialutils4", rpm:"lib64akonadi_socialutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akregatorinterfaces4", rpm:"lib64akregatorinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akregatorprivate4", rpm:"lib64akregatorprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64analitza-devel", rpm:"lib64analitza-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64analitza4", rpm:"lib64analitza4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64analitzagui4", rpm:"lib64analitzagui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64analitzaplot4", rpm:"lib64analitzaplot4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64audiocdplugins4", rpm:"lib64audiocdplugins4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64calendarsupport4", rpm:"lib64calendarsupport4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cantorlibs0", rpm:"lib64cantorlibs0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64compoundviewer4", rpm:"lib64compoundviewer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dolphinprivate4", rpm:"lib64dolphinprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64eventviews4", rpm:"lib64eventviews4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpgme++2", rpm:"lib64gpgme++2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gwenviewlib4", rpm:"lib64gwenviewlib4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64incidenceeditorsng4", rpm:"lib64incidenceeditorsng4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64incidenceeditorsngmobile4", rpm:"lib64incidenceeditorsngmobile4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64iris_ksirk2", rpm:"lib64iris_ksirk2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kabc4", rpm:"lib64kabc4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kabc_file_core4", rpm:"lib64kabc_file_core4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kactivities-devel", rpm:"lib64kactivities-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kactivities6", rpm:"lib64kactivities6~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kactivities_model-devel", rpm:"lib64kactivities_model-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kactivities_models1", rpm:"lib64kactivities_models1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kaddressbookprivate4", rpm:"lib64kaddressbookprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kalarmcal2", rpm:"lib64kalarmcal2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kanagramengine4", rpm:"lib64kanagramengine4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kasten2controllers2", rpm:"lib64kasten2controllers2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kasten2core2", rpm:"lib64kasten2core2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kasten2gui2", rpm:"lib64kasten2gui2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kasten2okteta1controllers1", rpm:"lib64kasten2okteta1controllers1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kasten2okteta1core1", rpm:"lib64kasten2okteta1core1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kasten2okteta1gui1", rpm:"lib64kasten2okteta1gui1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kateinterfaces4", rpm:"lib64kateinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64katepartinterfaces4", rpm:"lib64katepartinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kblog4", rpm:"lib64kblog4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kbookmarkmodel_private4", rpm:"lib64kbookmarkmodel_private4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcal4", rpm:"lib64kcal4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcal_resourceblog4", rpm:"lib64kcal_resourceblog4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcal_resourceremote4", rpm:"lib64kcal_resourceremote4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcalcore4", rpm:"lib64kcalcore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcalutils4", rpm:"lib64kcalutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcddb-devel", rpm:"lib64kcddb-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcddb4", rpm:"lib64kcddb4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcmutils4", rpm:"lib64kcmutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcompactdisc-devel", rpm:"lib64kcompactdisc-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcompactdisc4", rpm:"lib64kcompactdisc4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdcraw-devel", rpm:"lib64kdcraw-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdcraw22", rpm:"lib64kdcraw22~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kde3support4", rpm:"lib64kde3support4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeclarative5", rpm:"lib64kdeclarative5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdecorations4", rpm:"lib64kdecorations4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdecore5", rpm:"lib64kdecore5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeedu-devel", rpm:"lib64kdeedu-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdefakes5", rpm:"lib64kdefakes5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdegames-devel", rpm:"lib64kdegames-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdegames6", rpm:"lib64kdegames6~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdegamesprivate1", rpm:"lib64kdegamesprivate1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdepim-copy4", rpm:"lib64kdepim-copy4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdepim4", rpm:"lib64kdepim4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdepimdbusinterfaces4", rpm:"lib64kdepimdbusinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdesu5", rpm:"lib64kdesu5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeui5", rpm:"lib64kdeui5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdewebkit5", rpm:"lib64kdewebkit5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdgantt20", rpm:"lib64kdgantt20~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdnssd4", rpm:"lib64kdnssd4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64keduvocdocument4", rpm:"lib64keduvocdocument4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kemoticons4", rpm:"lib64kemoticons4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kephal4", rpm:"lib64kephal4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kerfuffle4", rpm:"lib64kerfuffle4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kexiv2-devel", rpm:"lib64kexiv2-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kexiv2_11", rpm:"lib64kexiv2_11~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfile4", rpm:"lib64kfile4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfontinst4", rpm:"lib64kfontinst4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfontinstui4", rpm:"lib64kfontinstui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kgetcore4", rpm:"lib64kgetcore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64khangmanengine4", rpm:"lib64khangmanengine4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kholidays4", rpm:"lib64kholidays4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64khotkeysprivate4", rpm:"lib64khotkeysprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64khtml5", rpm:"lib64khtml5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kidletime4", rpm:"lib64kidletime4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kimap4", rpm:"lib64kimap4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kimproxy4", rpm:"lib64kimproxy4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kio5", rpm:"lib64kio5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kipi-devel", rpm:"lib64kipi-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kipi10", rpm:"lib64kipi10~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kiten4", rpm:"lib64kiten4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjs4", rpm:"lib64kjs4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjsapi4", rpm:"lib64kjsapi4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjsembed4", rpm:"lib64kjsembed4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kldap4", rpm:"lib64kldap4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kleo4", rpm:"lib64kleo4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kleopatraclientcore0", rpm:"lib64kleopatraclientcore0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kleopatraclientgui0", rpm:"lib64kleopatraclientgui0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64klinkstatuscommon4", rpm:"lib64klinkstatuscommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmahjongglib4", rpm:"lib64kmahjongglib4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmailprivate4", rpm:"lib64kmailprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmanagesieve4", rpm:"lib64kmanagesieve4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmbox4", rpm:"lib64kmbox4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmediaplayer4", rpm:"lib64kmediaplayer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmime4", rpm:"lib64kmime4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmindexreader4", rpm:"lib64kmindexreader4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knewstuff2_4", rpm:"lib64knewstuff2_4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knewstuff3_4", rpm:"lib64knewstuff3_4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knodecommon4", rpm:"lib64knodecommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knotifyconfig4", rpm:"lib64knotifyconfig4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kntlm4", rpm:"lib64kntlm4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kolfprivate-devel", rpm:"lib64kolfprivate-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kolfprivate4", rpm:"lib64kolfprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kolourpaint_lgpl4", rpm:"lib64kolourpaint_lgpl4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kommandercore4", rpm:"lib64kommandercore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kommanderwidgets4", rpm:"lib64kommanderwidgets4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64komparedialogpages4", rpm:"lib64komparedialogpages4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64komparediff2_4", rpm:"lib64komparediff2_4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kompareinterface4", rpm:"lib64kompareinterface4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64konq5", rpm:"lib64konq5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64konqsidebarplugin4", rpm:"lib64konqsidebarplugin4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64konquerorprivate4", rpm:"lib64konquerorprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kontactinterface4", rpm:"lib64kontactinterface4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kontactprivate4", rpm:"lib64kontactprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopete4", rpm:"lib64kopete4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopete_oscar4", rpm:"lib64kopete_oscar4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopete_videodevice4", rpm:"lib64kopete_videodevice4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopeteaddaccountwizard1", rpm:"lib64kopeteaddaccountwizard1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopetechatwindow_shared1", rpm:"lib64kopetechatwindow_shared1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopetecontactlist1", rpm:"lib64kopetecontactlist1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopeteidentity1", rpm:"lib64kopeteidentity1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopeteprivacy1", rpm:"lib64kopeteprivacy1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopetestatusmenu1", rpm:"lib64kopetestatusmenu1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64korganizer_core4", rpm:"lib64korganizer_core4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64korganizer_interfaces4", rpm:"lib64korganizer_interfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64korganizerprivate4", rpm:"lib64korganizerprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kparts4", rpm:"lib64kparts4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpgp4", rpm:"lib64kpgp4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpimidentities4", rpm:"lib64kpimidentities4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpimtextedit4", rpm:"lib64kpimtextedit4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpimutils4", rpm:"lib64kpimutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kprintutils4", rpm:"lib64kprintutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpty4", rpm:"lib64kpty4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krdccore4", rpm:"lib64krdccore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kremotecontrol1", rpm:"lib64kremotecontrol1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kresources4", rpm:"lib64kresources4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krfbprivate4", rpm:"lib64krfbprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krosscore4", rpm:"lib64krosscore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krossui4", rpm:"lib64krossui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksane0", rpm:"lib64ksane0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kscreensaver5", rpm:"lib64kscreensaver5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksgrd4", rpm:"lib64ksgrd4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksieve4", rpm:"lib64ksieve4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksieveui4", rpm:"lib64ksieveui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksignalplotter4", rpm:"lib64ksignalplotter4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksirk-devel", rpm:"lib64ksirk-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ktexteditor-codesnippets0", rpm:"lib64ktexteditor-codesnippets0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ktexteditor4", rpm:"lib64ktexteditor4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ktnef4", rpm:"lib64ktnef4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ktrace4", rpm:"lib64ktrace4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kttsd4", rpm:"lib64kttsd4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kunitconversion4", rpm:"lib64kunitconversion4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kunittest4", rpm:"lib64kunittest4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kutils4", rpm:"lib64kutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwalletbackend4", rpm:"lib64kwalletbackend4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwineffects1", rpm:"lib64kwineffects1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinglesutils1", rpm:"lib64kwinglesutils1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinglutils1", rpm:"lib64kwinglutils1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinnvidiahack4", rpm:"lib64kwinnvidiahack4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kworkspace4", rpm:"lib64kworkspace4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kxmlrpcclient4", rpm:"lib64kxmlrpcclient4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kyahoo1", rpm:"lib64kyahoo1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lancelot-datamodels1", rpm:"lib64lancelot-datamodels1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lancelot2", rpm:"lib64lancelot2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lsofui4", rpm:"lib64lsofui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mailcommon4", rpm:"lib64mailcommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64maildir4", rpm:"lib64maildir4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mailimporter4", rpm:"lib64mailimporter4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mailtransport4", rpm:"lib64mailtransport4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64marblewidget15", rpm:"lib64marblewidget15~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messagecomposer4", rpm:"lib64messagecomposer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messagecore4", rpm:"lib64messagecore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messagelist4", rpm:"lib64messagelist4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messageviewer4", rpm:"lib64messageviewer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64microblog4", rpm:"lib64microblog4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64molletnetwork4", rpm:"lib64molletnetwork4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomuk4", rpm:"lib64nepomuk4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukcore4", rpm:"lib64nepomukcore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukquery4", rpm:"lib64nepomukquery4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukutils4", rpm:"lib64nepomukutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukwidget4", rpm:"lib64nepomukwidget4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64okteta1core1", rpm:"lib64okteta1core1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64okteta1gui1", rpm:"lib64okteta1gui1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64okularcore2", rpm:"lib64okularcore2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oscar1", rpm:"lib64oscar1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oxygenstyle4", rpm:"lib64oxygenstyle4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oxygenstyleconfig4", rpm:"lib64oxygenstyleconfig4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pala0", rpm:"lib64pala0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pimcommon4", rpm:"lib64pimcommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma-geolocation-interface4", rpm:"lib64plasma-geolocation-interface4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma3", rpm:"lib64plasma3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma_applet_system_monitor4", rpm:"lib64plasma_applet_system_monitor4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmaclock4", rpm:"lib64plasmaclock4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmacomicprovidercore1", rpm:"lib64plasmacomicprovidercore1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmacontainmentsgrouping4", rpm:"lib64plasmacontainmentsgrouping4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmagenericshell4", rpm:"lib64plasmagenericshell4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmapotdprovidercore1", rpm:"lib64plasmapotdprovidercore1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmaweather4", rpm:"lib64plasmaweather4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64powerdevilconfigcommonprivate4", rpm:"lib64powerdevilconfigcommonprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64powerdevilcore0", rpm:"lib64powerdevilcore0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64powerdevilui4", rpm:"lib64powerdevilui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64processcore4", rpm:"lib64processcore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64processui4", rpm:"lib64processui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qgpgme1", rpm:"lib64qgpgme1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtruby4shared2", rpm:"lib64qtruby4shared2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qyoto2", rpm:"lib64qyoto2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rocscore4", rpm:"lib64rocscore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rocsvisualeditor4", rpm:"lib64rocsvisualeditor4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rtm4", rpm:"lib64rtm4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64science4", rpm:"lib64science4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeakonadi3", rpm:"lib64smokeakonadi3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeattica3", rpm:"lib64smokeattica3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokebase3", rpm:"lib64smokebase3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekate3", rpm:"lib64smokekate3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekdecore3", rpm:"lib64smokekdecore3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekdeui3", rpm:"lib64smokekdeui3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekfile3", rpm:"lib64smokekfile3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekhtml3", rpm:"lib64smokekhtml3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekio3", rpm:"lib64smokekio3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeknewstuff2_3", rpm:"lib64smokeknewstuff2_3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeknewstuff3_3", rpm:"lib64smokeknewstuff3_3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekparts3", rpm:"lib64smokekparts3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokekutils3", rpm:"lib64smokekutils3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokenepomuk3", rpm:"lib64smokenepomuk3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokenepomukquery3", rpm:"lib64smokenepomukquery3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeokular3", rpm:"lib64smokeokular3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokephonon3", rpm:"lib64smokephonon3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeplasma3", rpm:"lib64smokeplasma3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqimageblitz3", rpm:"lib64smokeqimageblitz3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqsci3", rpm:"lib64smokeqsci3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqt3support3", rpm:"lib64smokeqt3support3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtcore3", rpm:"lib64smokeqtcore3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtdbus3", rpm:"lib64smokeqtdbus3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtdeclarative3", rpm:"lib64smokeqtdeclarative3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtgui3", rpm:"lib64smokeqtgui3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqthelp3", rpm:"lib64smokeqthelp3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtmultimedia3", rpm:"lib64smokeqtmultimedia3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtnetwork3", rpm:"lib64smokeqtnetwork3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtopengl3", rpm:"lib64smokeqtopengl3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtscript3", rpm:"lib64smokeqtscript3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtsql3", rpm:"lib64smokeqtsql3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtsvg3", rpm:"lib64smokeqtsvg3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqttest3", rpm:"lib64smokeqttest3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtuitools3", rpm:"lib64smokeqtuitools3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtwebkit3", rpm:"lib64smokeqtwebkit3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtxml3", rpm:"lib64smokeqtxml3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqtxmlpatterns3", rpm:"lib64smokeqtxmlpatterns3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokeqwt3", rpm:"lib64smokeqwt3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokesolid3", rpm:"lib64smokesolid3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokesoprano3", rpm:"lib64smokesoprano3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokesopranoclient3", rpm:"lib64smokesopranoclient3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smokesopranoserver3", rpm:"lib64smokesopranoserver3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smoketexteditor3", rpm:"lib64smoketexteditor3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64solid4", rpm:"lib64solid4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64solidcontrol4", rpm:"lib64solidcontrol4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64solidcontrolifaces4", rpm:"lib64solidcontrolifaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64superkaramba4", rpm:"lib64superkaramba4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64syndication4", rpm:"lib64syndication4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemsettingsview2", rpm:"lib64systemsettingsview2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64taskmanager4", rpm:"lib64taskmanager4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64templateparser4", rpm:"lib64templateparser4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64threadweaver4", rpm:"lib64threadweaver4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64weather_ion6", rpm:"lib64weather_ion6~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-calendar4", rpm:"libakonadi-calendar4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-contact4", rpm:"libakonadi-contact4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-filestore4", rpm:"libakonadi-filestore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-kabc4", rpm:"libakonadi-kabc4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-kcal4", rpm:"libakonadi-kcal4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-kde4", rpm:"libakonadi-kde4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-kmime4", rpm:"libakonadi-kmime4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-next4", rpm:"libakonadi-next4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-notes4", rpm:"libakonadi-notes4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-xml4", rpm:"libakonadi-xml4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi_socialutils4", rpm:"libakonadi_socialutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakregatorinterfaces4", rpm:"libakregatorinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakregatorprivate4", rpm:"libakregatorprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libanalitza-devel", rpm:"libanalitza-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libanalitza4", rpm:"libanalitza4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libanalitzagui4", rpm:"libanalitzagui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libanalitzaplot4", rpm:"libanalitzaplot4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudiocdplugins4", rpm:"libaudiocdplugins4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcalendarsupport4", rpm:"libcalendarsupport4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcantorlibs0", rpm:"libcantorlibs0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcompoundviewer4", rpm:"libcompoundviewer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdolphinprivate4", rpm:"libdolphinprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeventviews4", rpm:"libeventviews4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpgme++2", rpm:"libgpgme++2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgwenviewlib4", rpm:"libgwenviewlib4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libincidenceeditorsng4", rpm:"libincidenceeditorsng4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libincidenceeditorsngmobile4", rpm:"libincidenceeditorsngmobile4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiris_ksirk2", rpm:"libiris_ksirk2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkabc4", rpm:"libkabc4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkabc_file_core4", rpm:"libkabc_file_core4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkactivities", rpm:"libkactivities~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkactivities-devel", rpm:"libkactivities-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkactivities6", rpm:"libkactivities6~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkactivities_model-devel", rpm:"libkactivities_model-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkactivities_models1", rpm:"libkactivities_models1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkaddressbookprivate4", rpm:"libkaddressbookprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkalarmcal2", rpm:"libkalarmcal2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkanagramengine4", rpm:"libkanagramengine4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkasten2controllers2", rpm:"libkasten2controllers2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkasten2core2", rpm:"libkasten2core2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkasten2gui2", rpm:"libkasten2gui2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkasten2okteta1controllers1", rpm:"libkasten2okteta1controllers1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkasten2okteta1core1", rpm:"libkasten2okteta1core1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkasten2okteta1gui1", rpm:"libkasten2okteta1gui1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkateinterfaces4", rpm:"libkateinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkatepartinterfaces4", rpm:"libkatepartinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkblog4", rpm:"libkblog4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkbookmarkmodel_private4", rpm:"libkbookmarkmodel_private4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcal4", rpm:"libkcal4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcal_resourceblog4", rpm:"libkcal_resourceblog4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcal_resourceremote4", rpm:"libkcal_resourceremote4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcalcore4", rpm:"libkcalcore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcalutils4", rpm:"libkcalutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcddb", rpm:"libkcddb~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcddb-devel", rpm:"libkcddb-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcddb4", rpm:"libkcddb4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcmutils4", rpm:"libkcmutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcompactdisc", rpm:"libkcompactdisc~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcompactdisc-devel", rpm:"libkcompactdisc-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcompactdisc4", rpm:"libkcompactdisc4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw", rpm:"libkdcraw~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw-common", rpm:"libkdcraw-common~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw-devel", rpm:"libkdcraw-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw22", rpm:"libkdcraw22~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde3support4", rpm:"libkde3support4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeclarative5", rpm:"libkdeclarative5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecorations4", rpm:"libkdecorations4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore5", rpm:"libkdecore5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeedu", rpm:"libkdeedu~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeedu-common", rpm:"libkdeedu-common~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeedu-devel", rpm:"libkdeedu-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdefakes5", rpm:"libkdefakes5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdegames", rpm:"libkdegames~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdegames-common", rpm:"libkdegames-common~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdegames-devel", rpm:"libkdegames-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdegames6", rpm:"libkdegames6~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdegamesprivate1", rpm:"libkdegamesprivate1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdepim-copy4", rpm:"libkdepim-copy4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdepim4", rpm:"libkdepim4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdepimdbusinterfaces4", rpm:"libkdepimdbusinterfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdesu5", rpm:"libkdesu5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeui5", rpm:"libkdeui5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdewebkit5", rpm:"libkdewebkit5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdgantt20", rpm:"libkdgantt20~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdnssd4", rpm:"libkdnssd4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkeduvocdocument4", rpm:"libkeduvocdocument4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkemoticons4", rpm:"libkemoticons4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkephal4", rpm:"libkephal4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkerfuffle4", rpm:"libkerfuffle4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkexiv2", rpm:"libkexiv2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkexiv2-devel", rpm:"libkexiv2-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkexiv2_11", rpm:"libkexiv2_11~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfile4", rpm:"libkfile4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfontinst4", rpm:"libkfontinst4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfontinstui4", rpm:"libkfontinstui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkgetcore4", rpm:"libkgetcore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkhangmanengine4", rpm:"libkhangmanengine4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkholidays4", rpm:"libkholidays4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkhotkeysprivate4", rpm:"libkhotkeysprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkhtml5", rpm:"libkhtml5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkidletime4", rpm:"libkidletime4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkimap4", rpm:"libkimap4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkimproxy4", rpm:"libkimproxy4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkio5", rpm:"libkio5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkipi", rpm:"libkipi~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkipi-devel", rpm:"libkipi-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkipi10", rpm:"libkipi10~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkiten4", rpm:"libkiten4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjs4", rpm:"libkjs4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjsapi4", rpm:"libkjsapi4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjsembed4", rpm:"libkjsembed4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkldap4", rpm:"libkldap4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkleo4", rpm:"libkleo4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkleopatraclientcore0", rpm:"libkleopatraclientcore0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkleopatraclientgui0", rpm:"libkleopatraclientgui0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libklinkstatuscommon4", rpm:"libklinkstatuscommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmahjongg", rpm:"libkmahjongg~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmahjongg-devel", rpm:"libkmahjongg-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmahjongglib4", rpm:"libkmahjongglib4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmailprivate4", rpm:"libkmailprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmanagesieve4", rpm:"libkmanagesieve4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmbox4", rpm:"libkmbox4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmediaplayer4", rpm:"libkmediaplayer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmime4", rpm:"libkmime4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmindexreader4", rpm:"libkmindexreader4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknewstuff2_4", rpm:"libknewstuff2_4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknewstuff3_4", rpm:"libknewstuff3_4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknodecommon4", rpm:"libknodecommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknotifyconfig4", rpm:"libknotifyconfig4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkntlm4", rpm:"libkntlm4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkolfprivate-devel", rpm:"libkolfprivate-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkolfprivate4", rpm:"libkolfprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkolourpaint_lgpl4", rpm:"libkolourpaint_lgpl4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkommandercore4", rpm:"libkommandercore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkommanderwidgets4", rpm:"libkommanderwidgets4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkomparedialogpages4", rpm:"libkomparedialogpages4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkomparediff2_4", rpm:"libkomparediff2_4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkompareinterface4", rpm:"libkompareinterface4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkonq5", rpm:"libkonq5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkonqsidebarplugin4", rpm:"libkonqsidebarplugin4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkonquerorprivate4", rpm:"libkonquerorprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkontactinterface4", rpm:"libkontactinterface4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkontactprivate4", rpm:"libkontactprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopete4", rpm:"libkopete4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopete_oscar4", rpm:"libkopete_oscar4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopete_videodevice4", rpm:"libkopete_videodevice4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopeteaddaccountwizard1", rpm:"libkopeteaddaccountwizard1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopetechatwindow_shared1", rpm:"libkopetechatwindow_shared1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopetecontactlist1", rpm:"libkopetecontactlist1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopeteidentity1", rpm:"libkopeteidentity1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopeteprivacy1", rpm:"libkopeteprivacy1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopetestatusmenu1", rpm:"libkopetestatusmenu1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkorganizer_core4", rpm:"libkorganizer_core4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkorganizer_interfaces4", rpm:"libkorganizer_interfaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkorganizerprivate4", rpm:"libkorganizerprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkparts4", rpm:"libkparts4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpgp4", rpm:"libkpgp4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpimidentities4", rpm:"libkpimidentities4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpimtextedit4", rpm:"libkpimtextedit4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpimutils4", rpm:"libkpimutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkprintutils4", rpm:"libkprintutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpty4", rpm:"libkpty4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrdccore4", rpm:"libkrdccore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkremotecontrol1", rpm:"libkremotecontrol1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkresources4", rpm:"libkresources4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrfbprivate4", rpm:"libkrfbprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrosscore4", rpm:"libkrosscore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrossui4", rpm:"libkrossui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksane", rpm:"libksane~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksane-devel", rpm:"libksane-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksane0", rpm:"libksane0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkscreensaver5", rpm:"libkscreensaver5~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksgrd4", rpm:"libksgrd4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksieve4", rpm:"libksieve4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksieveui4", rpm:"libksieveui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksignalplotter4", rpm:"libksignalplotter4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksirk-devel", rpm:"libksirk-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libktexteditor-codesnippets0", rpm:"libktexteditor-codesnippets0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libktexteditor4", rpm:"libktexteditor4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libktnef4", rpm:"libktnef4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libktrace4", rpm:"libktrace4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkttsd4", rpm:"libkttsd4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkunitconversion4", rpm:"libkunitconversion4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkunittest4", rpm:"libkunittest4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkutils4", rpm:"libkutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwalletbackend4", rpm:"libkwalletbackend4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwineffects1", rpm:"libkwineffects1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinglesutils1", rpm:"libkwinglesutils1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinglutils1", rpm:"libkwinglutils1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinnvidiahack4", rpm:"libkwinnvidiahack4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkworkspace4", rpm:"libkworkspace4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkxmlrpcclient4", rpm:"libkxmlrpcclient4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkyahoo1", rpm:"libkyahoo1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblancelot-datamodels1", rpm:"liblancelot-datamodels1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblancelot2", rpm:"liblancelot2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsofui4", rpm:"liblsofui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmailcommon4", rpm:"libmailcommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmaildir4", rpm:"libmaildir4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmailimporter4", rpm:"libmailimporter4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmailtransport4", rpm:"libmailtransport4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmarblewidget15", rpm:"libmarblewidget15~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessagecomposer4", rpm:"libmessagecomposer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessagecore4", rpm:"libmessagecore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessagelist4", rpm:"libmessagelist4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessageviewer4", rpm:"libmessageviewer4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmicroblog4", rpm:"libmicroblog4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmolletnetwork4", rpm:"libmolletnetwork4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomuk4", rpm:"libnepomuk4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukcore4", rpm:"libnepomukcore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukquery4", rpm:"libnepomukquery4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukutils4", rpm:"libnepomukutils4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukwidget4", rpm:"libnepomukwidget4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libokteta1core1", rpm:"libokteta1core1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libokteta1gui1", rpm:"libokteta1gui1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libokularcore2", rpm:"libokularcore2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboscar1", rpm:"liboscar1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboxygenstyle4", rpm:"liboxygenstyle4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboxygenstyleconfig4", rpm:"liboxygenstyleconfig4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpala0", rpm:"libpala0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpimcommon4", rpm:"libpimcommon4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma-geolocation-interface4", rpm:"libplasma-geolocation-interface4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma3", rpm:"libplasma3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma_applet_system_monitor4", rpm:"libplasma_applet_system_monitor4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmaclock4", rpm:"libplasmaclock4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmacomicprovidercore1", rpm:"libplasmacomicprovidercore1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmacontainmentsgrouping4", rpm:"libplasmacontainmentsgrouping4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmagenericshell4", rpm:"libplasmagenericshell4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmapotdprovidercore1", rpm:"libplasmapotdprovidercore1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmaweather4", rpm:"libplasmaweather4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpowerdevilconfigcommonprivate4", rpm:"libpowerdevilconfigcommonprivate4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpowerdevilcore0", rpm:"libpowerdevilcore0~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpowerdevilui4", rpm:"libpowerdevilui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocesscore4", rpm:"libprocesscore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocessui4", rpm:"libprocessui4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqgpgme1", rpm:"libqgpgme1~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtruby4shared2", rpm:"libqtruby4shared2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqyoto2", rpm:"libqyoto2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librocscore4", rpm:"librocscore4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librocsvisualeditor4", rpm:"librocsvisualeditor4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librtm4", rpm:"librtm4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libscience4", rpm:"libscience4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeakonadi3", rpm:"libsmokeakonadi3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeattica3", rpm:"libsmokeattica3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokebase3", rpm:"libsmokebase3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekate3", rpm:"libsmokekate3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekdecore3", rpm:"libsmokekdecore3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekdeui3", rpm:"libsmokekdeui3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekfile3", rpm:"libsmokekfile3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekhtml3", rpm:"libsmokekhtml3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekio3", rpm:"libsmokekio3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeknewstuff2_3", rpm:"libsmokeknewstuff2_3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeknewstuff3_3", rpm:"libsmokeknewstuff3_3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekparts3", rpm:"libsmokekparts3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokekutils3", rpm:"libsmokekutils3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokenepomuk3", rpm:"libsmokenepomuk3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokenepomukquery3", rpm:"libsmokenepomukquery3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeokular3", rpm:"libsmokeokular3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokephonon3", rpm:"libsmokephonon3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeplasma3", rpm:"libsmokeplasma3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqimageblitz3", rpm:"libsmokeqimageblitz3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqsci3", rpm:"libsmokeqsci3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqt3support3", rpm:"libsmokeqt3support3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtcore3", rpm:"libsmokeqtcore3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtdbus3", rpm:"libsmokeqtdbus3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtdeclarative3", rpm:"libsmokeqtdeclarative3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtgui3", rpm:"libsmokeqtgui3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqthelp3", rpm:"libsmokeqthelp3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtmultimedia3", rpm:"libsmokeqtmultimedia3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtnetwork3", rpm:"libsmokeqtnetwork3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtopengl3", rpm:"libsmokeqtopengl3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtscript3", rpm:"libsmokeqtscript3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtsql3", rpm:"libsmokeqtsql3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtsvg3", rpm:"libsmokeqtsvg3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqttest3", rpm:"libsmokeqttest3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtuitools3", rpm:"libsmokeqtuitools3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtwebkit3", rpm:"libsmokeqtwebkit3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtxml3", rpm:"libsmokeqtxml3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqtxmlpatterns3", rpm:"libsmokeqtxmlpatterns3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokeqwt3", rpm:"libsmokeqwt3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokesolid3", rpm:"libsmokesolid3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokesoprano3", rpm:"libsmokesoprano3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokesopranoclient3", rpm:"libsmokesopranoclient3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmokesopranoserver3", rpm:"libsmokesopranoserver3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmoketexteditor3", rpm:"libsmoketexteditor3~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolid4", rpm:"libsolid4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolidcontrol4", rpm:"libsolidcontrol4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolidcontrolifaces4", rpm:"libsolidcontrolifaces4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsuperkaramba4", rpm:"libsuperkaramba4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsyndication4", rpm:"libsyndication4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemsettingsview2", rpm:"libsystemsettingsview2~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtaskmanager4", rpm:"libtaskmanager4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtemplateparser4", rpm:"libtemplateparser4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libthreadweaver4", rpm:"libthreadweaver4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libweather_ion6", rpm:"libweather_ion6~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lokalize", rpm:"lokalize~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lskat", rpm:"lskat~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lskat-handbook", rpm:"lskat-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"marble", rpm:"marble~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"marble-common", rpm:"marble-common~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"marble-devel", rpm:"marble-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"marble-handbook", rpm:"marble-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"messageviewer", rpm:"messageviewer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-icon-theme", rpm:"mono-icon-theme~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mplayerthumbs", rpm:"mplayerthumbs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nepomuk", rpm:"nepomuk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nepomuk-core", rpm:"nepomuk-core~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nepomuk-core-devel", rpm:"nepomuk-core-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nepomuk-widgets", rpm:"nepomuk-widgets~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nepomuk-widgets-devel", rpm:"nepomuk-widgets-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"okteta", rpm:"okteta~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"okular", rpm:"okular~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"okular-devel", rpm:"okular-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"okular-handbook", rpm:"okular-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oxygen-icon-theme", rpm:"oxygen-icon-theme~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pairs", rpm:"pairs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pairs-editor", rpm:"pairs-editor~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"palapeli", rpm:"palapeli~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"palapeli-devel", rpm:"palapeli-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"palapeli-handbook", rpm:"palapeli-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"parley", rpm:"parley~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-kde4", rpm:"perl-kde4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-qt4", rpm:"perl-qt4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-qt4-devel", rpm:"perl-qt4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-qt4-examples", rpm:"perl-qt4-examples~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"picmi", rpm:"picmi~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"picmi-handbook", rpm:"picmi-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-battery", rpm:"plasma-applet-battery~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-bball", rpm:"plasma-applet-bball~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-binaryclock", rpm:"plasma-applet-binaryclock~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-blackboard", rpm:"plasma-applet-blackboard~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-bookmarks", rpm:"plasma-applet-bookmarks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-bubblemon", rpm:"plasma-applet-bubblemon~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-calculator", rpm:"plasma-applet-calculator~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-calendar", rpm:"plasma-applet-calendar~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-charselect", rpm:"plasma-applet-charselect~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-comic", rpm:"plasma-applet-comic~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-dict", rpm:"plasma-applet-dict~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-didyouknow", rpm:"plasma-applet-didyouknow~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-eyes", rpm:"plasma-applet-eyes~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-fifteenpuzzle", rpm:"plasma-applet-fifteenpuzzle~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-filewatcher", rpm:"plasma-applet-filewatcher~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-folderview", rpm:"plasma-applet-folderview~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-frame", rpm:"plasma-applet-frame~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-fuzzy-clock", rpm:"plasma-applet-fuzzy-clock~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-icontasks", rpm:"plasma-applet-icontasks~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-incomingmsg", rpm:"plasma-applet-incomingmsg~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-kalzium-calculator", rpm:"plasma-applet-kalzium-calculator~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-kimpanel", rpm:"plasma-applet-kimpanel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-kimpanel-backend-ibus", rpm:"plasma-applet-kimpanel-backend-ibus~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-kimpanel-backend-scim", rpm:"plasma-applet-kimpanel-backend-scim~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-knowledgebase", rpm:"plasma-applet-knowledgebase~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-kolourpicker", rpm:"plasma-applet-kolourpicker~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-konqprofiles", rpm:"plasma-applet-konqprofiles~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-konsoleprofiles", rpm:"plasma-applet-konsoleprofiles~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-kworldclock", rpm:"plasma-applet-kworldclock~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-lancelot", rpm:"plasma-applet-lancelot~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-leavenote", rpm:"plasma-applet-leavenote~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-life", rpm:"plasma-applet-life~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-luna", rpm:"plasma-applet-luna~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-magnifique", rpm:"plasma-applet-magnifique~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-mediaplayer", rpm:"plasma-applet-mediaplayer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-microblog", rpm:"plasma-applet-microblog~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-news", rpm:"plasma-applet-news~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-notes", rpm:"plasma-applet-notes~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-nowplaying", rpm:"plasma-applet-nowplaying~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-opendesktop", rpm:"plasma-applet-opendesktop~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-paste", rpm:"plasma-applet-paste~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-pastebin", rpm:"plasma-applet-pastebin~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-plasmaboard", rpm:"plasma-applet-plasmaboard~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-previewer", rpm:"plasma-applet-previewer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-qalculate", rpm:"plasma-applet-qalculate~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-quicklaunch", rpm:"plasma-applet-quicklaunch~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-rssnow", rpm:"plasma-applet-rssnow~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-rtm", rpm:"plasma-applet-rtm~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-showdashboard", rpm:"plasma-applet-showdashboard~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-showdesktop", rpm:"plasma-applet-showdesktop~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-spellcheck", rpm:"plasma-applet-spellcheck~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-cpu", rpm:"plasma-applet-system-monitor-cpu~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-hdd", rpm:"plasma-applet-system-monitor-hdd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-hwinfo", rpm:"plasma-applet-system-monitor-hwinfo~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-net", rpm:"plasma-applet-system-monitor-net~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-temperature", rpm:"plasma-applet-system-monitor-temperature~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-systemloadviewer", rpm:"plasma-applet-systemloadviewer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-timer", rpm:"plasma-applet-timer~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-unitconverter", rpm:"plasma-applet-unitconverter~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-weather", rpm:"plasma-applet-weather~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-weatherstation", rpm:"plasma-applet-weatherstation~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-webbrowser", rpm:"plasma-applet-webbrowser~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-webslice", rpm:"plasma-applet-webslice~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-containments-grouping", rpm:"plasma-containments-grouping~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-comic", rpm:"plasma-dataengine-comic~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-kdeobservatory", rpm:"plasma-dataengine-kdeobservatory~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-kimpanel", rpm:"plasma-dataengine-kimpanel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-konqprofiles", rpm:"plasma-dataengine-konqprofiles~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-konsoleprofiles", rpm:"plasma-dataengine-konsoleprofiles~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-microblog", rpm:"plasma-dataengine-microblog~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-ocs", rpm:"plasma-dataengine-ocs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-potd", rpm:"plasma-dataengine-potd~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-dataengine-rtm", rpm:"plasma-dataengine-rtm~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-desktoptheme-androbit", rpm:"plasma-desktoptheme-androbit~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-desktoptheme-aya", rpm:"plasma-desktoptheme-aya~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-desktoptheme-produkt", rpm:"plasma-desktoptheme-produkt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-desktoptheme-slim-glow", rpm:"plasma-desktoptheme-slim-glow~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-desktoptheme-tibanna", rpm:"plasma-desktoptheme-tibanna~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-engine-kalzium", rpm:"plasma-engine-kalzium~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-krunner-nepomuk", rpm:"plasma-krunner-nepomuk~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-krunner-powerdevil", rpm:"plasma-krunner-powerdevil~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-audioplayercontrol", rpm:"plasma-runner-audioplayercontrol~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-browserhistory", rpm:"plasma-runner-browserhistory~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-charrunner", rpm:"plasma-runner-charrunner~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-contacts", rpm:"plasma-runner-contacts~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-converter", rpm:"plasma-runner-converter~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-datetime", rpm:"plasma-runner-datetime~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-dictionary", rpm:"plasma-runner-dictionary~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-events", rpm:"plasma-runner-events~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-katesessions", rpm:"plasma-runner-katesessions~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-konquerorsessions", rpm:"plasma-runner-konquerorsessions~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-konsolesessions", rpm:"plasma-runner-konsolesessions~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-kopete", rpm:"plasma-runner-kopete~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-mediawiki", rpm:"plasma-runner-mediawiki~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-places", rpm:"plasma-runner-places~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-spellchecker", rpm:"plasma-runner-spellchecker~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-youtube", rpm:"plasma-runner-youtube~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-scriptengine-python", rpm:"plasma-scriptengine-python~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-scriptengine-ruby", rpm:"plasma-scriptengine-ruby~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-wallpaper-mandelbrot", rpm:"plasma-wallpaper-mandelbrot~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-wallpaper-marble", rpm:"plasma-wallpaper-marble~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-wallpaper-pattern", rpm:"plasma-wallpaper-pattern~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-wallpaper-podt", rpm:"plasma-wallpaper-podt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-wallpaper-qml", rpm:"plasma-wallpaper-qml~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-wallpaper-virus", rpm:"plasma-wallpaper-virus~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-wallpaper-weather", rpm:"plasma-wallpaper-weather~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"print-manager", rpm:"print-manager~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-kde4", rpm:"python-kde4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-kde4-devel", rpm:"python-kde4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-kde4-doc", rpm:"python-kde4-doc~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qyoto", rpm:"qyoto~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qyoto-devel", rpm:"qyoto-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rocs", rpm:"rocs~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rocs-devel", rpm:"rocs-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-qt4", rpm:"ruby-qt4~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-qt4-devel", rpm:"ruby-qt4-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smokegen", rpm:"smokegen~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smokegen-devel", rpm:"smokegen-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smokekde", rpm:"smokekde~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smokekde-devel", rpm:"smokekde-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smokeqt", rpm:"smokeqt~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smokeqt-devel", rpm:"smokeqt-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"step", rpm:"step~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"superkaramba", rpm:"superkaramba~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"superkaramba-devel", rpm:"superkaramba-devel~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svgpart", rpm:"svgpart~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sweeper", rpm:"sweeper~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sweeper-handbook", rpm:"sweeper-handbook~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-kde4", rpm:"task-kde4~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-kde4-devel", rpm:"task-kde4-devel~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-kde4-handbooks", rpm:"task-kde4-handbooks~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-kde4-handbooks-dvd", rpm:"task-kde4-handbooks-dvd~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-kde4-minimal", rpm:"task-kde4-minimal~4.10.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"umbrello", rpm:"umbrello~4.10.5~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
