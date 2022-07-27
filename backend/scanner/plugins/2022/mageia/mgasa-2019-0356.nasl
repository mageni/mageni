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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0356");
  script_cve_id("CVE-2019-18281");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-18 20:15:00 +0000 (Tue, 18 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0356)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0356");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0356.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25651");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4556");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kwin, pyside2, pyside2-tools, qt3d5, qtbase5, qtcharts5, qtconnectivity5, qtdatavis3d5, qtdeclarative5, qtdoc5, qtenginio5, qtgamepad5, qtgraphicaleffects5, qtimageformats5, qtlocation5, qtmultimedia5, qtnetworkauth5, qtpurchasing5, qtquickcontrols25, qtquickcontrols5, qtremoteobjects5, qtscript5, qtscxml5, qtsensors5, qtserialbus5, qtserialport5, qtspeech5, qtsvg5, qttools5, qttranslations5, qtvirtualkeyboard5, qtwayland5, qtwebchannel5, qtwebengine5, qtwebglplugin5, qtwebkit5, qtwebsockets5, qtwebview5, qtx11extras5, qtxmlpatterns5, shiboken2, skrooge' package(s) announced via the MGASA-2019-0356 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the 5.12.6 QT stack maintenance release and fixes
the following security issue:

An out-of-bounds memory access in the generateDirectionalRuns() function
in qtextengine.cpp in Qt qtbase 5.11.x and 5.12.x before 5.12.5 allows
attackers to cause a denial of service by crashing an application via a
text file containing many directional characters (CVE-2019-18281).

kwin and skrooge has been rebuilt to pick up proper dependencies on the
updated QT packages.");

  script_tag(name:"affected", value:"'kwin, pyside2, pyside2-tools, qt3d5, qtbase5, qtcharts5, qtconnectivity5, qtdatavis3d5, qtdeclarative5, qtdoc5, qtenginio5, qtgamepad5, qtgraphicaleffects5, qtimageformats5, qtlocation5, qtmultimedia5, qtnetworkauth5, qtpurchasing5, qtquickcontrols25, qtquickcontrols5, qtremoteobjects5, qtscript5, qtscxml5, qtsensors5, qtserialbus5, qtserialport5, qtspeech5, qtsvg5, qttools5, qttranslations5, qtvirtualkeyboard5, qtwayland5, qtwebchannel5, qtwebengine5, qtwebglplugin5, qtwebkit5, qtwebsockets5, qtwebview5, qtx11extras5, qtxmlpatterns5, shiboken2, skrooge' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"kwin", rpm:"kwin~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwin-common", rpm:"kwin-common~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwin-handbook", rpm:"kwin-handbook~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwin-wayland", rpm:"kwin-wayland~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcmkwincommon5", rpm:"lib64kcmkwincommon5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwin-devel", rpm:"lib64kwin-devel~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwin4_effect_builtins1", rpm:"lib64kwin4_effect_builtins1~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwin5", rpm:"lib64kwin5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwineffects5", rpm:"lib64kwineffects5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinglutils5", rpm:"lib64kwinglutils5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinxrenderutils5", rpm:"lib64kwinxrenderutils5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pyside2-python3.7-devel", rpm:"lib64pyside2-python3.7-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pyside2-python3.7_5.12", rpm:"lib64pyside2-python3.7_5.12~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-mysql", rpm:"lib64qt5-database-plugin-mysql~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-odbc", rpm:"lib64qt5-database-plugin-odbc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-pgsql", rpm:"lib64qt5-database-plugin-pgsql~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-sqlite", rpm:"lib64qt5-database-plugin-sqlite~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-tds", rpm:"lib64qt5-database-plugin-tds~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53danimation5", rpm:"lib64qt53danimation5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dcore5", rpm:"lib64qt53dcore5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dextras5", rpm:"lib64qt53dextras5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dinput5", rpm:"lib64qt53dinput5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dlogic5", rpm:"lib64qt53dlogic5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dquick5", rpm:"lib64qt53dquick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dquickanimation5", rpm:"lib64qt53dquickanimation5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dquickextras5", rpm:"lib64qt53dquickextras5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dquickinput5", rpm:"lib64qt53dquickinput5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dquickrender5", rpm:"lib64qt53dquickrender5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53dquickscene2d5", rpm:"lib64qt53dquickscene2d5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt53drender5", rpm:"lib64qt53drender5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5accessibilitysupport-static-devel", rpm:"lib64qt5accessibilitysupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5base5-devel", rpm:"lib64qt5base5-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5bluetooth-devel", rpm:"lib64qt5bluetooth-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5bluetooth5", rpm:"lib64qt5bluetooth5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5bootstrap-static-devel", rpm:"lib64qt5bootstrap-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5charts-devel", rpm:"lib64qt5charts-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5charts5", rpm:"lib64qt5charts5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5concurrent-devel", rpm:"lib64qt5concurrent-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5concurrent5", rpm:"lib64qt5concurrent5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5core-devel", rpm:"lib64qt5core-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5core5", rpm:"lib64qt5core5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5datavisualization-devel", rpm:"lib64qt5datavisualization-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5datavisualization5", rpm:"lib64qt5datavisualization5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5dbus-devel", rpm:"lib64qt5dbus-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5dbus5", rpm:"lib64qt5dbus5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5designer-devel", rpm:"lib64qt5designer-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5designer5", rpm:"lib64qt5designer5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5devicediscoverysupport-static-devel", rpm:"lib64qt5devicediscoverysupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5edid-devel", rpm:"lib64qt5edid-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfsdeviceintegration-devel", rpm:"lib64qt5eglfsdeviceintegration-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfsdeviceintegration5", rpm:"lib64qt5eglfsdeviceintegration5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfskmssupport-devel", rpm:"lib64qt5eglfskmssupport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfskmssupport5", rpm:"lib64qt5eglfskmssupport5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglsupport-static-devel", rpm:"lib64qt5eglsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5enginio-devel", rpm:"lib64qt5enginio-devel~1.6.3~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eventdispatchersupport-static-devel", rpm:"lib64qt5eventdispatchersupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5fbsupport-static-devel", rpm:"lib64qt5fbsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5fontdatabasesupport-static-devel", rpm:"lib64qt5fontdatabasesupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gamepad-devel", rpm:"lib64qt5gamepad-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gamepad5", rpm:"lib64qt5gamepad5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5glxsupport-static-devel", rpm:"lib64qt5glxsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gui-devel", rpm:"lib64qt5gui-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gui5", rpm:"lib64qt5gui5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5help-devel", rpm:"lib64qt5help-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5help5", rpm:"lib64qt5help5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5hunspellinputmethod5", rpm:"lib64qt5hunspellinputmethod5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5imageformats-devel", rpm:"lib64qt5imageformats-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5inputsupport-static-devel", rpm:"lib64qt5inputsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5kmssupport-static-devel", rpm:"lib64qt5kmssupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5linuxaccessibilitysupport-static-devel", rpm:"lib64qt5linuxaccessibilitysupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5location-devel", rpm:"lib64qt5location-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5location5", rpm:"lib64qt5location5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimedia-devel", rpm:"lib64qt5multimedia-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimedia5", rpm:"lib64qt5multimedia5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimediagsttools-devel", rpm:"lib64qt5multimediagsttools-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimediagsttools5", rpm:"lib64qt5multimediagsttools5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimediaquick-devel", rpm:"lib64qt5multimediaquick-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimediaquick5", rpm:"lib64qt5multimediaquick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimediawidgets-devel", rpm:"lib64qt5multimediawidgets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5multimediawidgets5", rpm:"lib64qt5multimediawidgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5network-devel", rpm:"lib64qt5network-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5network5", rpm:"lib64qt5network5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5networkauth-devel", rpm:"lib64qt5networkauth-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5networkauth5", rpm:"lib64qt5networkauth5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5nfc-devel", rpm:"lib64qt5nfc-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5nfc5", rpm:"lib64qt5nfc5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5opengl-devel", rpm:"lib64qt5opengl-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5opengl5", rpm:"lib64qt5opengl5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5packetprotocol-static-devel", rpm:"lib64qt5packetprotocol-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5platformcompositorsupport-static-devel", rpm:"lib64qt5platformcompositorsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5platformsupport-devel", rpm:"lib64qt5platformsupport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5positioning-devel", rpm:"lib64qt5positioning-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5positioning5", rpm:"lib64qt5positioning5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5positioningquick5", rpm:"lib64qt5positioningquick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5printsupport-devel", rpm:"lib64qt5printsupport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5printsupport5", rpm:"lib64qt5printsupport5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5purchasing-devel", rpm:"lib64qt5purchasing-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5purchasing5", rpm:"lib64qt5purchasing5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5qml-devel", rpm:"lib64qt5qml-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5qml5", rpm:"lib64qt5qml5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5qt3d-devel", rpm:"lib64qt5qt3d-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quick-devel", rpm:"lib64qt5quick-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quick5", rpm:"lib64qt5quick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickcontrols2-devel", rpm:"lib64qt5quickcontrols2-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickcontrols2_5", rpm:"lib64qt5quickcontrols2_5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickparticles-devel", rpm:"lib64qt5quickparticles-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickparticles5", rpm:"lib64qt5quickparticles5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickshapes-devel", rpm:"lib64qt5quickshapes-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickshapes5", rpm:"lib64qt5quickshapes5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quicktemplates2-devel", rpm:"lib64qt5quicktemplates2-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quicktemplates2_5", rpm:"lib64qt5quicktemplates2_5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quicktest-devel", rpm:"lib64qt5quicktest-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quicktest5", rpm:"lib64qt5quicktest5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickwidgets-devel", rpm:"lib64qt5quickwidgets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5quickwidgets5", rpm:"lib64qt5quickwidgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5remoteobjects-devel", rpm:"lib64qt5remoteobjects-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5remoteobjects5", rpm:"lib64qt5remoteobjects5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5script-devel", rpm:"lib64qt5script-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5script5", rpm:"lib64qt5script5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5scripttools-devel", rpm:"lib64qt5scripttools-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5scripttools5", rpm:"lib64qt5scripttools5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5scxml-devel", rpm:"lib64qt5scxml-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5scxml5", rpm:"lib64qt5scxml5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sensors-devel", rpm:"lib64qt5sensors-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sensors5", rpm:"lib64qt5sensors5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5serialbus-devel", rpm:"lib64qt5serialbus-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5serialbus5", rpm:"lib64qt5serialbus5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5serialport-devel", rpm:"lib64qt5serialport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5serialport5", rpm:"lib64qt5serialport5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5servicesupport-static-devel", rpm:"lib64qt5servicesupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sql-devel", rpm:"lib64qt5sql-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sql5", rpm:"lib64qt5sql5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5svg-devel", rpm:"lib64qt5svg-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5svg5", rpm:"lib64qt5svg5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5test-devel", rpm:"lib64qt5test-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5test5", rpm:"lib64qt5test5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5texttospeech-devel", rpm:"lib64qt5texttospeech-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5texttospeech5", rpm:"lib64qt5texttospeech5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5themesupport-static-devel", rpm:"lib64qt5themesupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5virtualkeyboard-devel", rpm:"lib64qt5virtualkeyboard-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5virtualkeyboard5", rpm:"lib64qt5virtualkeyboard5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5waylandclient-devel", rpm:"lib64qt5waylandclient-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5waylandclient5", rpm:"lib64qt5waylandclient5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5waylandcompositor5", rpm:"lib64qt5waylandcompositor5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webchannel-devel", rpm:"lib64qt5webchannel-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webchannel5", rpm:"lib64qt5webchannel5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webengine-devel", rpm:"lib64qt5webengine-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webengine5", rpm:"lib64qt5webengine5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webenginecore5", rpm:"lib64qt5webenginecore5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webenginewidgets5", rpm:"lib64qt5webenginewidgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webglplugin-devel", rpm:"lib64qt5webglplugin-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webkit-devel", rpm:"lib64qt5webkit-devel~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webkit5", rpm:"lib64qt5webkit5~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webkitwidgets-devel", rpm:"lib64qt5webkitwidgets-devel~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webkitwidgets5", rpm:"lib64qt5webkitwidgets5~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5websockets-devel", rpm:"lib64qt5websockets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5websockets5", rpm:"lib64qt5websockets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webview-devel", rpm:"lib64qt5webview-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webview5", rpm:"lib64qt5webview5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5widgets-devel", rpm:"lib64qt5widgets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5widgets5", rpm:"lib64qt5widgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5x11extras-devel", rpm:"lib64qt5x11extras-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5x11extras5", rpm:"lib64qt5x11extras5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xcbqpa-devel", rpm:"lib64qt5xcbqpa-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xcbqpa5", rpm:"lib64qt5xcbqpa5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xml-devel", rpm:"lib64qt5xml-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xml5", rpm:"lib64qt5xml5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xmlpatterns-devel", rpm:"lib64qt5xmlpatterns-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xmlpatterns5", rpm:"lib64qt5xmlpatterns5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtenginio1", rpm:"lib64qtenginio1~1.6.3~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64shiboken2-python3.7-devel", rpm:"lib64shiboken2-python3.7-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64shiboken2-python3.7_5.12", rpm:"lib64shiboken2-python3.7_5.12~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64skgbankgui2", rpm:"lib64skgbankgui2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64skgbankmodeler2", rpm:"lib64skgbankmodeler2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64skgbasegui2", rpm:"lib64skgbasegui2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64skgbasemodeler2", rpm:"lib64skgbasemodeler2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcmkwincommon5", rpm:"libkcmkwincommon5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwin-devel", rpm:"libkwin-devel~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwin4_effect_builtins1", rpm:"libkwin4_effect_builtins1~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwin5", rpm:"libkwin5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwineffects5", rpm:"libkwineffects5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinglutils5", rpm:"libkwinglutils5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinxrenderutils5", rpm:"libkwinxrenderutils5~5.15.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpyside2-python3.7-devel", rpm:"libpyside2-python3.7-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpyside2-python3.7_5.12", rpm:"libpyside2-python3.7_5.12~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-mysql", rpm:"libqt5-database-plugin-mysql~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-odbc", rpm:"libqt5-database-plugin-odbc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-pgsql", rpm:"libqt5-database-plugin-pgsql~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-sqlite", rpm:"libqt5-database-plugin-sqlite~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-tds", rpm:"libqt5-database-plugin-tds~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53danimation5", rpm:"libqt53danimation5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dcore5", rpm:"libqt53dcore5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dextras5", rpm:"libqt53dextras5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dinput5", rpm:"libqt53dinput5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dlogic5", rpm:"libqt53dlogic5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dquick5", rpm:"libqt53dquick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dquickanimation5", rpm:"libqt53dquickanimation5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dquickextras5", rpm:"libqt53dquickextras5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dquickinput5", rpm:"libqt53dquickinput5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dquickrender5", rpm:"libqt53dquickrender5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53dquickscene2d5", rpm:"libqt53dquickscene2d5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt53drender5", rpm:"libqt53drender5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5accessibilitysupport-static-devel", rpm:"libqt5accessibilitysupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5base5-devel", rpm:"libqt5base5-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5bluetooth-devel", rpm:"libqt5bluetooth-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5bluetooth5", rpm:"libqt5bluetooth5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5bootstrap-static-devel", rpm:"libqt5bootstrap-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5charts-devel", rpm:"libqt5charts-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5charts5", rpm:"libqt5charts5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5concurrent-devel", rpm:"libqt5concurrent-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5concurrent5", rpm:"libqt5concurrent5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5core-devel", rpm:"libqt5core-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5core5", rpm:"libqt5core5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5datavisualization-devel", rpm:"libqt5datavisualization-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5datavisualization5", rpm:"libqt5datavisualization5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5dbus-devel", rpm:"libqt5dbus-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5dbus5", rpm:"libqt5dbus5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5designer-devel", rpm:"libqt5designer-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5designer5", rpm:"libqt5designer5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5devicediscoverysupport-static-devel", rpm:"libqt5devicediscoverysupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5edid-devel", rpm:"libqt5edid-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfsdeviceintegration-devel", rpm:"libqt5eglfsdeviceintegration-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfsdeviceintegration5", rpm:"libqt5eglfsdeviceintegration5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfskmssupport-devel", rpm:"libqt5eglfskmssupport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfskmssupport5", rpm:"libqt5eglfskmssupport5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglsupport-static-devel", rpm:"libqt5eglsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5enginio-devel", rpm:"libqt5enginio-devel~1.6.3~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eventdispatchersupport-static-devel", rpm:"libqt5eventdispatchersupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5fbsupport-static-devel", rpm:"libqt5fbsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5fontdatabasesupport-static-devel", rpm:"libqt5fontdatabasesupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gamepad-devel", rpm:"libqt5gamepad-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gamepad5", rpm:"libqt5gamepad5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5glxsupport-static-devel", rpm:"libqt5glxsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gui-devel", rpm:"libqt5gui-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gui5", rpm:"libqt5gui5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5help-devel", rpm:"libqt5help-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5help5", rpm:"libqt5help5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5hunspellinputmethod5", rpm:"libqt5hunspellinputmethod5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5imageformats-devel", rpm:"libqt5imageformats-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5inputsupport-static-devel", rpm:"libqt5inputsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5kmssupport-static-devel", rpm:"libqt5kmssupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5linuxaccessibilitysupport-static-devel", rpm:"libqt5linuxaccessibilitysupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5location-devel", rpm:"libqt5location-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5location5", rpm:"libqt5location5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimedia-devel", rpm:"libqt5multimedia-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimedia5", rpm:"libqt5multimedia5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimediagsttools-devel", rpm:"libqt5multimediagsttools-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimediagsttools5", rpm:"libqt5multimediagsttools5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimediaquick-devel", rpm:"libqt5multimediaquick-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimediaquick5", rpm:"libqt5multimediaquick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimediawidgets-devel", rpm:"libqt5multimediawidgets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5multimediawidgets5", rpm:"libqt5multimediawidgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5network-devel", rpm:"libqt5network-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5network5", rpm:"libqt5network5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5networkauth-devel", rpm:"libqt5networkauth-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5networkauth5", rpm:"libqt5networkauth5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5nfc-devel", rpm:"libqt5nfc-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5nfc5", rpm:"libqt5nfc5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5opengl-devel", rpm:"libqt5opengl-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5opengl5", rpm:"libqt5opengl5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5packetprotocol-static-devel", rpm:"libqt5packetprotocol-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5platformcompositorsupport-static-devel", rpm:"libqt5platformcompositorsupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5platformsupport-devel", rpm:"libqt5platformsupport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5positioning-devel", rpm:"libqt5positioning-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5positioning5", rpm:"libqt5positioning5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5positioningquick5", rpm:"libqt5positioningquick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5printsupport-devel", rpm:"libqt5printsupport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5printsupport5", rpm:"libqt5printsupport5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5purchasing-devel", rpm:"libqt5purchasing-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5purchasing5", rpm:"libqt5purchasing5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5qml-devel", rpm:"libqt5qml-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5qml5", rpm:"libqt5qml5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5qt3d-devel", rpm:"libqt5qt3d-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quick-devel", rpm:"libqt5quick-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quick5", rpm:"libqt5quick5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickcontrols2-devel", rpm:"libqt5quickcontrols2-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickcontrols2_5", rpm:"libqt5quickcontrols2_5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickparticles-devel", rpm:"libqt5quickparticles-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickparticles5", rpm:"libqt5quickparticles5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickshapes-devel", rpm:"libqt5quickshapes-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickshapes5", rpm:"libqt5quickshapes5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quicktemplates2-devel", rpm:"libqt5quicktemplates2-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quicktemplates2_5", rpm:"libqt5quicktemplates2_5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quicktest-devel", rpm:"libqt5quicktest-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quicktest5", rpm:"libqt5quicktest5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickwidgets-devel", rpm:"libqt5quickwidgets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5quickwidgets5", rpm:"libqt5quickwidgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5remoteobjects-devel", rpm:"libqt5remoteobjects-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5remoteobjects5", rpm:"libqt5remoteobjects5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5script-devel", rpm:"libqt5script-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5script5", rpm:"libqt5script5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5scripttools-devel", rpm:"libqt5scripttools-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5scripttools5", rpm:"libqt5scripttools5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5scxml-devel", rpm:"libqt5scxml-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5scxml5", rpm:"libqt5scxml5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sensors-devel", rpm:"libqt5sensors-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sensors5", rpm:"libqt5sensors5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5serialbus-devel", rpm:"libqt5serialbus-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5serialbus5", rpm:"libqt5serialbus5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5serialport-devel", rpm:"libqt5serialport-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5serialport5", rpm:"libqt5serialport5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5servicesupport-static-devel", rpm:"libqt5servicesupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sql-devel", rpm:"libqt5sql-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sql5", rpm:"libqt5sql5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5svg-devel", rpm:"libqt5svg-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5svg5", rpm:"libqt5svg5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5test-devel", rpm:"libqt5test-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5test5", rpm:"libqt5test5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5texttospeech-devel", rpm:"libqt5texttospeech-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5texttospeech5", rpm:"libqt5texttospeech5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5themesupport-static-devel", rpm:"libqt5themesupport-static-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5virtualkeyboard-devel", rpm:"libqt5virtualkeyboard-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5virtualkeyboard5", rpm:"libqt5virtualkeyboard5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5waylandclient-devel", rpm:"libqt5waylandclient-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5waylandclient5", rpm:"libqt5waylandclient5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5waylandcompositor5", rpm:"libqt5waylandcompositor5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webchannel-devel", rpm:"libqt5webchannel-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webchannel5", rpm:"libqt5webchannel5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webengine-devel", rpm:"libqt5webengine-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webengine5", rpm:"libqt5webengine5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webenginecore5", rpm:"libqt5webenginecore5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webenginewidgets5", rpm:"libqt5webenginewidgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webglplugin-devel", rpm:"libqt5webglplugin-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webkit-devel", rpm:"libqt5webkit-devel~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webkit5", rpm:"libqt5webkit5~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webkitwidgets-devel", rpm:"libqt5webkitwidgets-devel~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webkitwidgets5", rpm:"libqt5webkitwidgets5~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5websockets-devel", rpm:"libqt5websockets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5websockets5", rpm:"libqt5websockets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webview-devel", rpm:"libqt5webview-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webview5", rpm:"libqt5webview5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5widgets-devel", rpm:"libqt5widgets-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5widgets5", rpm:"libqt5widgets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5x11extras-devel", rpm:"libqt5x11extras-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5x11extras5", rpm:"libqt5x11extras5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xcbqpa-devel", rpm:"libqt5xcbqpa-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xcbqpa5", rpm:"libqt5xcbqpa5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xml-devel", rpm:"libqt5xml-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xml5", rpm:"libqt5xml5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xmlpatterns-devel", rpm:"libqt5xmlpatterns-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xmlpatterns5", rpm:"libqt5xmlpatterns5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtenginio1", rpm:"libqtenginio1~1.6.3~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libshiboken2-python3.7-devel", rpm:"libshiboken2-python3.7-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libshiboken2-python3.7_5.12", rpm:"libshiboken2-python3.7_5.12~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libskgbankgui2", rpm:"libskgbankgui2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libskgbankmodeler2", rpm:"libskgbankmodeler2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libskgbasegui2", rpm:"libskgbasegui2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libskgbasemodeler2", rpm:"libskgbasemodeler2~2.19.1~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pyside2", rpm:"pyside2~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pyside2-tools", rpm:"pyside2-tools~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-3danimation", rpm:"python3-pyside2-3danimation~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-3dcore", rpm:"python3-pyside2-3dcore~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-3dextras", rpm:"python3-pyside2-3dextras~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-3dinput", rpm:"python3-pyside2-3dinput~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-3dlogic", rpm:"python3-pyside2-3dlogic~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-3drender", rpm:"python3-pyside2-3drender~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2", rpm:"python3-pyside2~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-charts", rpm:"python3-pyside2-charts~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-concurrent", rpm:"python3-pyside2-concurrent~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-core", rpm:"python3-pyside2-core~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-datavisualization", rpm:"python3-pyside2-datavisualization~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-gui", rpm:"python3-pyside2-gui~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-help", rpm:"python3-pyside2-help~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-location", rpm:"python3-pyside2-location~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-multimedia", rpm:"python3-pyside2-multimedia~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-multimediawidgets", rpm:"python3-pyside2-multimediawidgets~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-network", rpm:"python3-pyside2-network~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-opengl", rpm:"python3-pyside2-opengl~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-openglfunctions", rpm:"python3-pyside2-openglfunctions~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-positioning", rpm:"python3-pyside2-positioning~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-printsupport", rpm:"python3-pyside2-printsupport~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-qml", rpm:"python3-pyside2-qml~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-quick", rpm:"python3-pyside2-quick~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-quickwidgets", rpm:"python3-pyside2-quickwidgets~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-remoteobjects", rpm:"python3-pyside2-remoteobjects~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-script", rpm:"python3-pyside2-script~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-scripttools", rpm:"python3-pyside2-scripttools~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-scxml", rpm:"python3-pyside2-scxml~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-sensors", rpm:"python3-pyside2-sensors~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-sql", rpm:"python3-pyside2-sql~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-svg", rpm:"python3-pyside2-svg~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-test", rpm:"python3-pyside2-test~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-texttospeech", rpm:"python3-pyside2-texttospeech~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-uitools", rpm:"python3-pyside2-uitools~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-webchannel", rpm:"python3-pyside2-webchannel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-webengine", rpm:"python3-pyside2-webengine~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-webenginecore", rpm:"python3-pyside2-webenginecore~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-webenginewidgets", rpm:"python3-pyside2-webenginewidgets~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-websockets", rpm:"python3-pyside2-websockets~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-widgets", rpm:"python3-pyside2-widgets~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-x11extras", rpm:"python3-pyside2-x11extras~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-xml", rpm:"python3-pyside2-xml~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside2-xmlpatterns", rpm:"python3-pyside2-xmlpatterns~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-shiboken2", rpm:"python3-shiboken2~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt3d5", rpm:"qt3d5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt3d5-doc", rpm:"qt3d5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5", rpm:"qtbase5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-common", rpm:"qtbase5-common~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-common-devel", rpm:"qtbase5-common-devel~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-doc", rpm:"qtbase5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-examples", rpm:"qtbase5-examples~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbluetooth5", rpm:"qtbluetooth5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtcharts5", rpm:"qtcharts5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtcharts5-doc", rpm:"qtcharts5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtconnectivity5", rpm:"qtconnectivity5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtconnectivity5-doc", rpm:"qtconnectivity5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtdatavis3d5", rpm:"qtdatavis3d5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtdatavis3d5-doc", rpm:"qtdatavis3d5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtdeclarative5", rpm:"qtdeclarative5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtdeclarative5-doc", rpm:"qtdeclarative5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtdoc5", rpm:"qtdoc5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtenginio5", rpm:"qtenginio5~1.6.3~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtenginio5-doc", rpm:"qtenginio5-doc~1.6.3~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtgamepad5", rpm:"qtgamepad5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtgamepad5-doc", rpm:"qtgamepad5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtgraphicaleffects5", rpm:"qtgraphicaleffects5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtgraphicaleffects5-doc", rpm:"qtgraphicaleffects5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtimageformats5", rpm:"qtimageformats5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtimageformats5-doc", rpm:"qtimageformats5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtlocation5", rpm:"qtlocation5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtlocation5-doc", rpm:"qtlocation5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtmultimedia5", rpm:"qtmultimedia5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtmultimedia5-doc", rpm:"qtmultimedia5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtnetworkauth5", rpm:"qtnetworkauth5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtnetworkauth5-doc", rpm:"qtnetworkauth5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtnfc5", rpm:"qtnfc5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtpositioning5", rpm:"qtpositioning5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtpurchasing5", rpm:"qtpurchasing5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtpurchasing5-doc", rpm:"qtpurchasing5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtquickcontrols25", rpm:"qtquickcontrols25~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtquickcontrols5", rpm:"qtquickcontrols5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtquickcontrols5-doc", rpm:"qtquickcontrols5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtremoteobjects5", rpm:"qtremoteobjects5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtremoteobjects5-doc", rpm:"qtremoteobjects5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtscript5", rpm:"qtscript5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtscript5-doc", rpm:"qtscript5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtscxml5", rpm:"qtscxml5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtscxml5-doc", rpm:"qtscxml5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsensors5", rpm:"qtsensors5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsensors5-doc", rpm:"qtsensors5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtserialbus5", rpm:"qtserialbus5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtserialbus5-doc", rpm:"qtserialbus5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtserialport5", rpm:"qtserialport5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtserialport5-doc", rpm:"qtserialport5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtspeech5", rpm:"qtspeech5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtspeech5-doc", rpm:"qtspeech5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsvg5", rpm:"qtsvg5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsvg5-doc", rpm:"qtsvg5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qttools5", rpm:"qttools5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qttools5-assistant", rpm:"qttools5-assistant~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qttools5-designer", rpm:"qttools5-designer~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qttools5-qtdbus", rpm:"qttools5-qtdbus~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qttranslations5", rpm:"qttranslations5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtvirtualkeyboard5", rpm:"qtvirtualkeyboard5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtvirtualkeyboard5-doc", rpm:"qtvirtualkeyboard5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwayland5", rpm:"qtwayland5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwayland5-doc", rpm:"qtwayland5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebchannel5", rpm:"qtwebchannel5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebchannel5-doc", rpm:"qtwebchannel5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebengine5", rpm:"qtwebengine5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebengine5-doc", rpm:"qtwebengine5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebglplugin5", rpm:"qtwebglplugin5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebkit5", rpm:"qtwebkit5~5.212.0~1.alpha3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebsockets5", rpm:"qtwebsockets5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebsockets5-doc", rpm:"qtwebsockets5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebview5", rpm:"qtwebview5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebview5-doc", rpm:"qtwebview5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtx11extras5", rpm:"qtx11extras5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtx11extras5-doc", rpm:"qtx11extras5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtxmlpatterns5", rpm:"qtxmlpatterns5~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtxmlpatterns5-doc", rpm:"qtxmlpatterns5-doc~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtxmlpatterns5-xmlpatterns", rpm:"qtxmlpatterns5-xmlpatterns~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shiboken2", rpm:"shiboken2~5.12.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skrooge", rpm:"skrooge~2.19.1~2.mga7", rls:"MAGEIA7"))) {
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
