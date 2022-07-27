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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0280");
  script_cve_id("CVE-2019-20839", "CVE-2020-14397", "CVE-2020-14398", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-29 00:15:00 +0000 (Sat, 29 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0280)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0280");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0280.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26881");
  script_xref(name:"URL", value:"https://github.com/LibVNC/libvncserver/releases/tag/LibVNCServer-0.9.13");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2264");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvncserver' package(s) announced via the MGASA-2020-0280 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libvncserver packages fix security vulnerabilities:

libvncclient/sockets.c in LibVNCServer had a buffer overflow via a long
socket filename (CVE-2019-20839).

libvncserver/rfbregion.c had a NULL pointer dereference (CVE-2020-14397).

Byte-aligned data was accessed through uint32_t pointers in
libvncclient/rfbproto.c (CVE-2020-14399).

Byte-aligned data was accessed through uint16_t pointers in
libvncserver/translate.c (CVE-2020-14400).

libvncserver/scale.c had a pixel_value integer overflow (CVE-2020-14401).

libvncserver/corre.c allowed out-of-bounds access via encodings
(CVE-2020-14402).

libvncserver/hextile.c allowed out-of-bounds access via encodings
(CVE-2020-14403).

libvncserver/rre.c allowed out-of-bounds access via encodings
(CVE-2020-14404).

libvncclient/rfbproto.c does not limit TextChat size (CVE-2020-14405).

The libvncserver package has been updated to version 0.9.13, fixing these
issues and several others. See the release announcement for details.");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver-devel", rpm:"lib64vncserver-devel~0.9.13~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver1", rpm:"lib64vncserver1~0.9.13~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.13~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver-devel", rpm:"libvncserver-devel~0.9.13~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver1", rpm:"libvncserver1~0.9.13~1.mga7", rls:"MAGEIA7"))) {
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
