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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0397");
  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0397)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0397");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0397.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14155");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2014-007.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-September/139445.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvncserver, libvncserver, remmina, remmina' package(s) announced via the MGASA-2014-0397 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libvncserver and remmina packages fix security vulnerabilities:

A malicious VNC server can trigger incorrect memory management handling by
advertising a large screen size parameter to the VNC client. This would result
in multiple memory corruptions and could allow remote code execution on the
VNC client (CVE-2014-6051, CVE-2014-6052).

A malicious VNC client can trigger multiple DoS conditions on the VNC server
by advertising a large screen size, ClientCutText message length and/or a zero
scaling factor parameter (CVE-2014-6053, CVE-2014-6054).

A malicious VNC client can trigger multiple stack-based buffer overflows by
passing a long file and directory names and/or attributes (FileTime) when
using the file transfer message feature (CVE-2014-6055).

The remmina package had been built with a bundled copy of libvncserver. It
has been rebuilt against the system libvncserver library to resolve these
issues.");

  script_tag(name:"affected", value:"'libvncserver, libvncserver, remmina, remmina' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver-devel", rpm:"lib64vncserver-devel~0.9.9~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver0", rpm:"lib64vncserver0~0.9.9~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.9~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver-devel", rpm:"libvncserver-devel~0.9.9~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.9~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linuxvnc", rpm:"linuxvnc~0.9.9~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina", rpm:"remmina~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-devel", rpm:"remmina-devel~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-common", rpm:"remmina-plugins-common~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-gnome", rpm:"remmina-plugins-gnome~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-nx", rpm:"remmina-plugins-nx~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-rdp", rpm:"remmina-plugins-rdp~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-telepathy", rpm:"remmina-plugins-telepathy~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-vnc", rpm:"remmina-plugins-vnc~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-xdmcp", rpm:"remmina-plugins-xdmcp~1.0.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver-devel", rpm:"lib64vncserver-devel~0.9.9~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver0", rpm:"lib64vncserver0~0.9.9~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.9~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver-devel", rpm:"libvncserver-devel~0.9.9~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.9~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linuxvnc", rpm:"linuxvnc~0.9.9~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina", rpm:"remmina~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-devel", rpm:"remmina-devel~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-common", rpm:"remmina-plugins-common~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-gnome", rpm:"remmina-plugins-gnome~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-nx", rpm:"remmina-plugins-nx~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-rdp", rpm:"remmina-plugins-rdp~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-telepathy", rpm:"remmina-plugins-telepathy~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-vnc", rpm:"remmina-plugins-vnc~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-xdmcp", rpm:"remmina-plugins-xdmcp~1.0.0~4.4.mga4", rls:"MAGEIA4"))) {
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
