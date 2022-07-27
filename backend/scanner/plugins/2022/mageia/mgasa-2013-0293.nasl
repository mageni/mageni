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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0293");
  script_cve_id("CVE-2013-4288", "CVE-2013-4324", "CVE-2013-4325", "CVE-2013-4326", "CVE-2013-4327");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:11:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2013-0293)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0293");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0293.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11260");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-1270.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-1273.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-1274.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1959-1/");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1961-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip, hplip, polkit, polkit, rtkit, rtkit, spice-gtk, spice-gtk, systemd, systemd' package(s) announced via the MGASA-2013-0293 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was found in the way the PolicyKit pkcheck utility
checked process authorization when the process was specified by its
process ID via the --process option. A local user could use this flaw to
bypass intended PolicyKit authorizations and escalate their privileges
(CVE-2013-4288).

Note: Applications that invoke pkcheck with the --process option need to
be modified to use the pid,pid-start-time,uid argument for that option, to
allow pkcheck to check process authorization correctly.

Because of the change in the PolicyKit API, the spice-gtk (CVE-2013-4324),
hplip (CVE-2013-4325), rtkit (CVE-2013-4326), and systemd (CVE-2013-4327)
packages have been updated to use a different API that is not affected by
this PolicyKit vulnerability. The libvirt package will also be updated
for the same reason, but this update will come in a separate advisory.");

  script_tag(name:"affected", value:"'hplip, hplip, polkit, polkit, rtkit, rtkit, spice-gtk, spice-gtk, systemd, systemd' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-doc", rpm:"hplip-doc~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs", rpm:"hplip-hpijs~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs-ppds", rpm:"hplip-hpijs-ppds~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-model-data", rpm:"hplip-model-data~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0", rpm:"lib64hpip0~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0-devel", rpm:"lib64hpip0-devel~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit-gir1.0", rpm:"lib64polkit-gir1.0~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1-devel", rpm:"lib64polkit1-devel~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1_0", rpm:"lib64polkit1_0~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sane-hpaio1", rpm:"lib64sane-hpaio1~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-glib-gir2.0", rpm:"lib64spice-client-glib-gir2.0~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-glib2.0_1", rpm:"lib64spice-client-glib2.0_1~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk-gir3.0", rpm:"lib64spice-client-gtk-gir3.0~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk3.0_1", rpm:"lib64spice-client-gtk3.0_1~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-controller0", rpm:"lib64spice-controller0~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-gtk-devel", rpm:"lib64spice-gtk-devel~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-daemon0", rpm:"lib64systemd-daemon0~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-daemon0-devel", rpm:"lib64systemd-daemon0-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-id1280", rpm:"lib64systemd-id1280~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-id1280-devel", rpm:"lib64systemd-id1280-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-journal0", rpm:"lib64systemd-journal0~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-journal0-devel", rpm:"lib64systemd-journal0-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-login0", rpm:"lib64systemd-login0~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-login0-devel", rpm:"lib64systemd-login0-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0", rpm:"libhpip0~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0-devel", rpm:"libhpip0-devel~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gir1.0", rpm:"libpolkit-gir1.0~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1-devel", rpm:"libpolkit1-devel~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1_0", rpm:"libpolkit1_0~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsane-hpaio1", rpm:"libsane-hpaio1~3.12.4~1.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib-gir2.0", rpm:"libspice-client-glib-gir2.0~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib2.0_1", rpm:"libspice-client-glib2.0_1~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk-gir3.0", rpm:"libspice-client-gtk-gir3.0~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk3.0_1", rpm:"libspice-client-gtk3.0_1~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-controller0", rpm:"libspice-controller0~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-gtk-devel", rpm:"libspice-gtk-devel~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-daemon0", rpm:"libsystemd-daemon0~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-daemon0-devel", rpm:"libsystemd-daemon0-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-id1280", rpm:"libsystemd-id1280~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-id1280-devel", rpm:"libsystemd-id1280-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-journal0", rpm:"libsystemd-journal0~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-journal0-devel", rpm:"libsystemd-journal0-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-login0", rpm:"libsystemd-login0~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-login0-devel", rpm:"libsystemd-login0-devel~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-desktop-policy", rpm:"polkit-desktop-policy~0.104~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtkit", rpm:"rtkit~0.10~3.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spice-gtk", rpm:"spice-gtk~0.9~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-tools", rpm:"systemd-tools~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-units", rpm:"systemd-units~44~13.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-doc", rpm:"hplip-doc~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs", rpm:"hplip-hpijs~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs-ppds", rpm:"hplip-hpijs-ppds~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-model-data", rpm:"hplip-model-data~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gudev-gir1.0", rpm:"lib64gudev-gir1.0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gudev1.0-devel", rpm:"lib64gudev1.0-devel~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gudev1.0_0", rpm:"lib64gudev1.0_0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0", rpm:"lib64hpip0~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0-devel", rpm:"lib64hpip0-devel~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit-gir1.0", rpm:"lib64polkit-gir1.0~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1-devel", rpm:"lib64polkit1-devel~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1_0", rpm:"lib64polkit1_0~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sane-hpaio1", rpm:"lib64sane-hpaio1~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-glib-gir2.0", rpm:"lib64spice-client-glib-gir2.0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-glib2.0_8", rpm:"lib64spice-client-glib2.0_8~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk-gir2.0", rpm:"lib64spice-client-gtk-gir2.0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk-gir3.0", rpm:"lib64spice-client-gtk-gir3.0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk2.0_4", rpm:"lib64spice-client-gtk2.0_4~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk3.0_4", rpm:"lib64spice-client-gtk3.0_4~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-controller0", rpm:"lib64spice-controller0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-gtk-devel", rpm:"lib64spice-gtk-devel~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-daemon0", rpm:"lib64systemd-daemon0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-id128_0", rpm:"lib64systemd-id128_0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-journal0", rpm:"lib64systemd-journal0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64systemd-login0", rpm:"lib64systemd-login0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64udev-devel", rpm:"lib64udev-devel~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64udev1", rpm:"lib64udev1~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-gir1.0", rpm:"libgudev-gir1.0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev1.0-devel", rpm:"libgudev1.0-devel~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev1.0_0", rpm:"libgudev1.0_0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0", rpm:"libhpip0~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0-devel", rpm:"libhpip0-devel~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gir1.0", rpm:"libpolkit-gir1.0~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1-devel", rpm:"libpolkit1-devel~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1_0", rpm:"libpolkit1_0~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsane-hpaio1", rpm:"libsane-hpaio1~3.12.9~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib-gir2.0", rpm:"libspice-client-glib-gir2.0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib2.0_8", rpm:"libspice-client-glib2.0_8~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk-gir2.0", rpm:"libspice-client-gtk-gir2.0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk-gir3.0", rpm:"libspice-client-gtk-gir3.0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk2.0_4", rpm:"libspice-client-gtk2.0_4~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk3.0_4", rpm:"libspice-client-gtk3.0_4~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-controller0", rpm:"libspice-controller0~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-gtk-devel", rpm:"libspice-gtk-devel~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-daemon0", rpm:"libsystemd-daemon0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-id128_0", rpm:"libsystemd-id128_0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-journal0", rpm:"libsystemd-journal0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd-login0", rpm:"libsystemd-login0~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-desktop-policy", rpm:"polkit-desktop-policy~0.107~6.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-spice-client-gtk", rpm:"python-spice-client-gtk~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-systemd", rpm:"python-systemd~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtkit", rpm:"rtkit~0.11~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spice-gtk", rpm:"spice-gtk~0.15~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-tools", rpm:"systemd-tools~195~22.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-units", rpm:"systemd-units~195~22.1.mga3", rls:"MAGEIA3"))) {
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
