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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0445");
  script_cve_id("CVE-2014-8651");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 03:01:00 +0000 (Wed, 07 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2014-0445)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0445");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0445.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14487");
  script_xref(name:"URL", value:"https://www.kde.org/info/security/advisory-20141106-1.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=3310");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=9086");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11050");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdebase4-workspace' package(s) announced via the MGASA-2014-0445 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a security vulnerability in the KDE workspace
configuration module for setting the date and time (CVE-2014-8651,
mga#14487), and fixes some additional issues:
 - fix kcm botching unrelated user settings (mga#3310, bko#254430),
 - do not popup during initialization 0 B Removable media (mga#11050,
 bko#318061),
 - fix new graphical session numbers (mga#9086).");

  script_tag(name:"affected", value:"'kdebase4-workspace' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace", rpm:"kdebase4-workspace~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace-devel", rpm:"kdebase4-workspace-devel~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace-handbooks", rpm:"kdebase4-workspace-handbooks~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-workspace-plasma-config", rpm:"kdebase4-workspace-plasma-config~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kded_randrmonitor", rpm:"kded_randrmonitor~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdm", rpm:"kdm~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdm-handbook", rpm:"kdm-handbook~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kinfocenter", rpm:"kinfocenter~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kinfocenter-handbook", rpm:"kinfocenter-handbook~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdecorations4", rpm:"lib64kdecorations4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kephal4", rpm:"lib64kephal4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfontinst4", rpm:"lib64kfontinst4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfontinstui4", rpm:"lib64kfontinstui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64khotkeysprivate4", rpm:"lib64khotkeysprivate4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kscreensaver5", rpm:"lib64kscreensaver5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksgrd4", rpm:"lib64ksgrd4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksignalplotter4", rpm:"lib64ksignalplotter4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwineffects1", rpm:"lib64kwineffects1~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinglesutils1", rpm:"lib64kwinglesutils1~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinglutils1", rpm:"lib64kwinglutils1~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwinnvidiahack4", rpm:"lib64kwinnvidiahack4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kworkspace4", rpm:"lib64kworkspace4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lsofui4", rpm:"lib64lsofui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oxygenstyle4", rpm:"lib64oxygenstyle4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oxygenstyleconfig4", rpm:"lib64oxygenstyleconfig4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma-geolocation-interface4", rpm:"lib64plasma-geolocation-interface4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma_applet_system_monitor4", rpm:"lib64plasma_applet_system_monitor4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmaclock4", rpm:"lib64plasmaclock4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasmagenericshell4", rpm:"lib64plasmagenericshell4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64powerdevilconfigcommonprivate4", rpm:"lib64powerdevilconfigcommonprivate4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64powerdevilcore0", rpm:"lib64powerdevilcore0~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64powerdevilui4", rpm:"lib64powerdevilui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64processcore4", rpm:"lib64processcore4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64processui4", rpm:"lib64processui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64solidcontrol4", rpm:"lib64solidcontrol4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64solidcontrolifaces4", rpm:"lib64solidcontrolifaces4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemsettingsview2", rpm:"lib64systemsettingsview2~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64taskmanager4", rpm:"lib64taskmanager4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64weather_ion6", rpm:"lib64weather_ion6~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecorations4", rpm:"libkdecorations4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkephal4", rpm:"libkephal4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfontinst4", rpm:"libkfontinst4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfontinstui4", rpm:"libkfontinstui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkhotkeysprivate4", rpm:"libkhotkeysprivate4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkscreensaver5", rpm:"libkscreensaver5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksgrd4", rpm:"libksgrd4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksignalplotter4", rpm:"libksignalplotter4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwineffects1", rpm:"libkwineffects1~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinglesutils1", rpm:"libkwinglesutils1~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinglutils1", rpm:"libkwinglutils1~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwinnvidiahack4", rpm:"libkwinnvidiahack4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkworkspace4", rpm:"libkworkspace4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsofui4", rpm:"liblsofui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboxygenstyle4", rpm:"liboxygenstyle4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboxygenstyleconfig4", rpm:"liboxygenstyleconfig4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma-geolocation-interface4", rpm:"libplasma-geolocation-interface4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma_applet_system_monitor4", rpm:"libplasma_applet_system_monitor4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmaclock4", rpm:"libplasmaclock4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasmagenericshell4", rpm:"libplasmagenericshell4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpowerdevilconfigcommonprivate4", rpm:"libpowerdevilconfigcommonprivate4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpowerdevilcore0", rpm:"libpowerdevilcore0~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpowerdevilui4", rpm:"libpowerdevilui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocesscore4", rpm:"libprocesscore4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocessui4", rpm:"libprocessui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolidcontrol4", rpm:"libsolidcontrol4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolidcontrolifaces4", rpm:"libsolidcontrolifaces4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemsettingsview2", rpm:"libsystemsettingsview2~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtaskmanager4", rpm:"libtaskmanager4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libweather_ion6", rpm:"libweather_ion6~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-battery", rpm:"plasma-applet-battery~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-calendar", rpm:"plasma-applet-calendar~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-quicklaunch", rpm:"plasma-applet-quicklaunch~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-cpu", rpm:"plasma-applet-system-monitor-cpu~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-hdd", rpm:"plasma-applet-system-monitor-hdd~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-hwinfo", rpm:"plasma-applet-system-monitor-hwinfo~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-net", rpm:"plasma-applet-system-monitor-net~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-system-monitor-temperature", rpm:"plasma-applet-system-monitor-temperature~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-applet-webbrowser", rpm:"plasma-applet-webbrowser~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-krunner-nepomuk", rpm:"plasma-krunner-nepomuk~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-krunner-powerdevil", rpm:"plasma-krunner-powerdevil~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-runner-places", rpm:"plasma-runner-places~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-scriptengine-python", rpm:"plasma-scriptengine-python~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-scriptengine-ruby", rpm:"plasma-scriptengine-ruby~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
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
