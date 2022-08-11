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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0260");
  script_cve_id("CVE-2020-10754");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-23 17:44:00 +0000 (Tue, 23 Jun 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0260)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0260");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0260.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26713");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26673");
  script_xref(name:"URL", value:"https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/nm-1-18/NEWS");
  script_xref(name:"URL", value:"https://gitlab.gnome.org/GNOME/network-manager-applet/-/blob/1.8.24/NEWS");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SI4LWYUPI7M6B24ABADK24T77VF65B4A/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-control-center, gnome-shell, networkmanager, networkmanager-applet' package(s) announced via the MGASA-2020-0260 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that nmcli, a command line interface to NetworkManager did
not honour 802-1x.ca-path and 802-1x.phase2-ca-path settings, when
creating a new profile. When a user connects to a network using this
profile, the authentication does not happen and the connection is made
insecurely (CVE-2020-10754).

The networkmanager package has been updated to version 1.18.8, fixing
this issue and other bugs.

Also, the networkmanager-applet package has been updated to version
1.8.24. It also adds support for connecting to WPA3 / SAE protected
wireless networks.

gnome-control-center and gnome-shell have been fixed to correctly
identify the connections as WPA3.");

  script_tag(name:"affected", value:"'gnome-control-center, gnome-shell, networkmanager, networkmanager-applet' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnome-control-center", rpm:"gnome-control-center~3.32.1~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-keybindings-devel", rpm:"gnome-keybindings-devel~3.32.1~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.32.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64networkmanager-gir1.0", rpm:"lib64networkmanager-gir1.0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-devel", rpm:"lib64nm-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-gir1.0", rpm:"lib64nm-gir1.0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib-devel", rpm:"lib64nm-glib-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib-vpn-devel", rpm:"lib64nm-glib-vpn-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib-vpn1", rpm:"lib64nm-glib-vpn1~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib4", rpm:"lib64nm-glib4~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-gtk-devel", rpm:"lib64nm-gtk-devel~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-gtk0", rpm:"lib64nm-gtk0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-util-devel", rpm:"lib64nm-util-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-util2", rpm:"lib64nm-util2~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm0", rpm:"lib64nm0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nma-devel", rpm:"lib64nma-devel~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nma-gir1.0", rpm:"lib64nma-gir1.0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nma0", rpm:"lib64nma0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nmclient-gir1.0", rpm:"lib64nmclient-gir1.0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nmgtk-gir1.0", rpm:"lib64nmgtk-gir1.0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetworkmanager-gir1.0", rpm:"libnetworkmanager-gir1.0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-devel", rpm:"libnm-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-gir1.0", rpm:"libnm-gir1.0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib-devel", rpm:"libnm-glib-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib-vpn-devel", rpm:"libnm-glib-vpn-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib-vpn1", rpm:"libnm-glib-vpn1~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib4", rpm:"libnm-glib4~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-gtk-devel", rpm:"libnm-gtk-devel~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-gtk0", rpm:"libnm-gtk0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-util-devel", rpm:"libnm-util-devel~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-util2", rpm:"libnm-util2~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm0", rpm:"libnm0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnma-devel", rpm:"libnma-devel~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnma-gir1.0", rpm:"libnma-gir1.0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnma0", rpm:"libnma0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnmclient-gir1.0", rpm:"libnmclient-gir1.0~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnmgtk-gir1.0", rpm:"libnmgtk-gir1.0~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager", rpm:"networkmanager~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-adsl", rpm:"networkmanager-adsl~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-applet", rpm:"networkmanager-applet~1.8.24~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-bluetooth", rpm:"networkmanager-bluetooth~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-ppp", rpm:"networkmanager-ppp~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-team", rpm:"networkmanager-team~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-tui", rpm:"networkmanager-tui~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-wifi", rpm:"networkmanager-wifi~1.18.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-wwan", rpm:"networkmanager-wwan~1.18.8~1.mga7", rls:"MAGEIA7"))) {
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
