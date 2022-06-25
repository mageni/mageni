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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0186");
  script_cve_id("CVE-2013-1872", "CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1993", "CVE-2013-1994", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063", "CVE-2013-2064", "CVE-2013-2066");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2013-0186)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0186");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0186.html");
  script_xref(name:"URL", value:"http://www.x.org/wiki/Development/Security/Advisory-2013-05-23");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-0897.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2673");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2674");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2675");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2676");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2677");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2678");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2679");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2680");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2681");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2682");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2683");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2684");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2685");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2686");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2687");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2688");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2689");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2690");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2691");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2692");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2693");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10565");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libdmx, libfs, libx11, libxcb, libxcursor, libxext, libxfixes, libxi, libxinerama, libxp, libxrandr, libxrender, libxres, libxt, libxtst, libxv, libxvmc, libxxf86dga, libxxf86vm, mesa, mesa, x11-driver-video-openchrome' package(s) announced via the MGASA-2013-0186 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ilja van Sprundel of IOActive discovered several security issues in multiple
components of the X.org graphics stack and the related libraries: Various
integer overflows, sign handling errors in integer conversions, buffer
overflows, memory corruption and missing input sanitising may lead to
privilege escalation or denial of service (CVE-2013-1981, CVE-2013-1982,
CVE-2013-1983, CVE-2013-1984, CVE-2013-1985, CVE-2013-1986, CVE-2013-1987,
CVE-2013-1988, CVE-2013-1989, CVE-2013-1990, CVE-2013-1991, CVE-2013-1992,
CVE-2013-1993, CVE-2013-1994, CVE-2013-1995, CVE-2013-1996, CVE-2013-1997,
CVE-2013-1998, CVE-2013-1999, CVE-2013-2000, CVE-2013-2001, CVE-2013-2002,
CVE-2013-2003, CVE-2013-2004, CVE-2013-2005, CVE-2013-2062, CVE-2013-2063,
CVE-2013-2064, CVE-2013-2066).

An out-of-bounds access flaw was found in Mesa. If an application using
Mesa exposed the Mesa API to untrusted inputs (Mozilla Firefox does
this), an attacker could cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application (CVE-2013-1872).");

  script_tag(name:"affected", value:"'libdmx, libfs, libx11, libxcb, libxcursor, libxext, libxfixes, libxi, libxinerama, libxp, libxrandr, libxrender, libxres, libxt, libxtst, libxv, libxvmc, libxxf86dga, libxxf86vm, mesa, mesa, x11-driver-video-openchrome' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64dmx-devel", rpm:"lib64dmx-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dmx-static-devel", rpm:"lib64dmx-static-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dmx1", rpm:"lib64dmx1~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dri-drivers", rpm:"lib64dri-drivers~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dri-drivers", rpm:"lib64dri-drivers~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1", rpm:"lib64dricore1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1", rpm:"lib64dricore1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1-devel", rpm:"lib64dricore1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1-devel", rpm:"lib64dricore1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fs-devel", rpm:"lib64fs-devel~1.0.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fs-static-devel", rpm:"lib64fs-static-devel~1.0.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fs6", rpm:"lib64fs6~1.0.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1", rpm:"lib64gbm1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1", rpm:"lib64gbm1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1-devel", rpm:"lib64gbm1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1-devel", rpm:"lib64gbm1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0", rpm:"lib64glapi0~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0", rpm:"lib64glapi0~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0-devel", rpm:"lib64glapi0-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0-devel", rpm:"lib64glapi0-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64llvmradeon9.1.3", rpm:"lib64llvmradeon9.1.3~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64llvmradeon9.1.3", rpm:"lib64llvmradeon9.1.3~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1", rpm:"lib64mesaegl1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1", rpm:"lib64mesaegl1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1-devel", rpm:"lib64mesaegl1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1-devel", rpm:"lib64mesaegl1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1", rpm:"lib64mesagl1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1", rpm:"lib64mesagl1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1-devel", rpm:"lib64mesagl1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1-devel", rpm:"lib64mesagl1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1", rpm:"lib64mesaglesv1_1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1", rpm:"lib64mesaglesv1_1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1-devel", rpm:"lib64mesaglesv1_1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1-devel", rpm:"lib64mesaglesv1_1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2", rpm:"lib64mesaglesv2_2~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2", rpm:"lib64mesaglesv2_2~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2-devel", rpm:"lib64mesaglesv2_2-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2-devel", rpm:"lib64mesaglesv2_2-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1", rpm:"lib64mesaopenvg1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1", rpm:"lib64mesaopenvg1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1-devel", rpm:"lib64mesaopenvg1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1-devel", rpm:"lib64mesaopenvg1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa-devel", rpm:"lib64osmesa-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa-devel", rpm:"lib64osmesa-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa8", rpm:"lib64osmesa8~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa8", rpm:"lib64osmesa8~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-nouveau", rpm:"lib64vdpau-driver-nouveau~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-nouveau", rpm:"lib64vdpau-driver-nouveau~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r300", rpm:"lib64vdpau-driver-r300~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r300", rpm:"lib64vdpau-driver-r300~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r600", rpm:"lib64vdpau-driver-r600~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r600", rpm:"lib64vdpau-driver-r600~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-radeonsi", rpm:"lib64vdpau-driver-radeonsi~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-radeonsi", rpm:"lib64vdpau-driver-radeonsi~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-softpipe", rpm:"lib64vdpau-driver-softpipe~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-softpipe", rpm:"lib64vdpau-driver-softpipe~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1", rpm:"lib64wayland-egl1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1", rpm:"lib64wayland-egl1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1-devel", rpm:"lib64wayland-egl1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1-devel", rpm:"lib64wayland-egl1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6", rpm:"lib64x11_6~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6-devel", rpm:"lib64x11_6-devel~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6-static-devel", rpm:"lib64x11_6-static-devel~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-composite0", rpm:"lib64xcb-composite0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-damage0", rpm:"lib64xcb-damage0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-devel", rpm:"lib64xcb-devel~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-dpms0", rpm:"lib64xcb-dpms0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-dri2_0", rpm:"lib64xcb-dri2_0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-glx0", rpm:"lib64xcb-glx0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-randr0", rpm:"lib64xcb-randr0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-record0", rpm:"lib64xcb-record0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-render0", rpm:"lib64xcb-render0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-res0", rpm:"lib64xcb-res0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-screensaver0", rpm:"lib64xcb-screensaver0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-shape0", rpm:"lib64xcb-shape0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-shm0", rpm:"lib64xcb-shm0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-static-devel", rpm:"lib64xcb-static-devel~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-sync0", rpm:"lib64xcb-sync0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xevie0", rpm:"lib64xcb-xevie0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xf86dri0", rpm:"lib64xcb-xf86dri0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xfixes0", rpm:"lib64xcb-xfixes0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xinerama0", rpm:"lib64xcb-xinerama0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xprint0", rpm:"lib64xcb-xprint0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xtest0", rpm:"lib64xcb-xtest0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xv0", rpm:"lib64xcb-xv0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xvmc0", rpm:"lib64xcb-xvmc0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb1", rpm:"lib64xcb1~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcursor-devel", rpm:"lib64xcursor-devel~1.1.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcursor-static-devel", rpm:"lib64xcursor-static-devel~1.1.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcursor1", rpm:"lib64xcursor1~1.1.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xext6", rpm:"lib64xext6~1.3.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xext6-devel", rpm:"lib64xext6-devel~1.3.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xext6-static-devel", rpm:"lib64xext6-static-devel~1.3.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfixes3", rpm:"lib64xfixes3~5.0.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfixes3-devel", rpm:"lib64xfixes3-devel~5.0.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfixes3-static-devel", rpm:"lib64xfixes3-static-devel~5.0.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xi-devel", rpm:"lib64xi-devel~1.6.2.901~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xi-static-devel", rpm:"lib64xi-static-devel~1.6.2.901~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xi6", rpm:"lib64xi6~1.6.2.901~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xinerama1", rpm:"lib64xinerama1~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xinerama1-devel", rpm:"lib64xinerama1-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xinerama1-static-devel", rpm:"lib64xinerama1-static-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xp-devel", rpm:"lib64xp-devel~1.0.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xp-static-devel", rpm:"lib64xp-static-devel~1.0.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xp6", rpm:"lib64xp6~1.0.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrandr2", rpm:"lib64xrandr2~1.4.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrandr2-devel", rpm:"lib64xrandr2-devel~1.4.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrandr2-static-devel", rpm:"lib64xrandr2-static-devel~1.4.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrender1", rpm:"lib64xrender1~0.9.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrender1-devel", rpm:"lib64xrender1-devel~0.9.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrender1-static-devel", rpm:"lib64xrender1-static-devel~0.9.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xres1", rpm:"lib64xres1~1.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xres1-devel", rpm:"lib64xres1-devel~1.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xres1-static-devel", rpm:"lib64xres1-static-devel~1.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xt-devel", rpm:"lib64xt-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xt-static-devel", rpm:"lib64xt-static-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xt6", rpm:"lib64xt6~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xtst6", rpm:"lib64xtst6~1.2.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xtst6-devel", rpm:"lib64xtst6-devel~1.2.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xtst6-static-devel", rpm:"lib64xtst6-static-devel~1.2.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xv1", rpm:"lib64xv1~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xv1-devel", rpm:"lib64xv1-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xv1-static-devel", rpm:"lib64xv1-static-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xvmc1", rpm:"lib64xvmc1~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xvmc1-devel", rpm:"lib64xvmc1-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xvmc1-static-devel", rpm:"lib64xvmc1-static-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xxf86dga-devel", rpm:"lib64xxf86dga-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xxf86dga-static-devel", rpm:"lib64xxf86dga-static-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xxf86dga1", rpm:"lib64xxf86dga1~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xxf86vm-devel", rpm:"lib64xxf86vm-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xxf86vm-static-devel", rpm:"lib64xxf86vm-static-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xxf86vm1", rpm:"lib64xxf86vm1~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmx", rpm:"libdmx~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmx-devel", rpm:"libdmx-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmx-static-devel", rpm:"libdmx-static-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmx1", rpm:"libdmx1~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdri-drivers", rpm:"libdri-drivers~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdri-drivers", rpm:"libdri-drivers~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1", rpm:"libdricore1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1", rpm:"libdricore1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1-devel", rpm:"libdricore1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1-devel", rpm:"libdricore1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfs", rpm:"libfs~1.0.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfs-devel", rpm:"libfs-devel~1.0.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfs-static-devel", rpm:"libfs-static-devel~1.0.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfs6", rpm:"libfs6~1.0.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-devel", rpm:"libgbm1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-devel", rpm:"libgbm1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0", rpm:"libglapi0~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0", rpm:"libglapi0~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0-devel", rpm:"libglapi0-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0-devel", rpm:"libglapi0-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libllvmradeon9.1.3", rpm:"libllvmradeon9.1.3~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libllvmradeon9.1.3", rpm:"libllvmradeon9.1.3~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1", rpm:"libmesaegl1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1", rpm:"libmesaegl1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1-devel", rpm:"libmesaegl1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1-devel", rpm:"libmesaegl1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1", rpm:"libmesagl1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1", rpm:"libmesagl1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1-devel", rpm:"libmesagl1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1-devel", rpm:"libmesagl1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1", rpm:"libmesaglesv1_1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1", rpm:"libmesaglesv1_1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1-devel", rpm:"libmesaglesv1_1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1-devel", rpm:"libmesaglesv1_1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2", rpm:"libmesaglesv2_2~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2", rpm:"libmesaglesv2_2~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2-devel", rpm:"libmesaglesv2_2-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2-devel", rpm:"libmesaglesv2_2-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1", rpm:"libmesaopenvg1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1", rpm:"libmesaopenvg1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1-devel", rpm:"libmesaopenvg1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1-devel", rpm:"libmesaopenvg1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa-devel", rpm:"libosmesa-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa-devel", rpm:"libosmesa-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa8", rpm:"libosmesa8~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa8", rpm:"libosmesa8~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-nouveau", rpm:"libvdpau-driver-nouveau~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-nouveau", rpm:"libvdpau-driver-nouveau~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r300", rpm:"libvdpau-driver-r300~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r300", rpm:"libvdpau-driver-r300~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r600", rpm:"libvdpau-driver-r600~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r600", rpm:"libvdpau-driver-r600~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-radeonsi", rpm:"libvdpau-driver-radeonsi~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-radeonsi", rpm:"libvdpau-driver-radeonsi~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-softpipe", rpm:"libvdpau-driver-softpipe~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-softpipe", rpm:"libvdpau-driver-softpipe~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1", rpm:"libwayland-egl1~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1", rpm:"libwayland-egl1~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1-devel", rpm:"libwayland-egl1-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1-devel", rpm:"libwayland-egl1-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11", rpm:"libx11~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-common", rpm:"libx11-common~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-doc", rpm:"libx11-doc~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6", rpm:"libx11_6~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6-devel", rpm:"libx11_6-devel~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6-static-devel", rpm:"libx11_6-static-devel~1.6.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb", rpm:"libxcb~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0", rpm:"libxcb-composite0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0", rpm:"libxcb-damage0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-doc", rpm:"libxcb-doc~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0", rpm:"libxcb-dpms0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2_0", rpm:"libxcb-dri2_0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0", rpm:"libxcb-glx0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0", rpm:"libxcb-randr0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0", rpm:"libxcb-record0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0", rpm:"libxcb-render0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0", rpm:"libxcb-res0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0", rpm:"libxcb-screensaver0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0", rpm:"libxcb-shape0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0", rpm:"libxcb-shm0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-static-devel", rpm:"libxcb-static-devel~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync0", rpm:"libxcb-sync0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xevie0", rpm:"libxcb-xevie0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0", rpm:"libxcb-xf86dri0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0", rpm:"libxcb-xfixes0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0", rpm:"libxcb-xinerama0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xprint0", rpm:"libxcb-xprint0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0", rpm:"libxcb-xtest0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0", rpm:"libxcb-xv0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0", rpm:"libxcb-xvmc0~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1", rpm:"libxcb1~1.9.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcursor", rpm:"libxcursor~1.1.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcursor-devel", rpm:"libxcursor-devel~1.1.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcursor-static-devel", rpm:"libxcursor-static-devel~1.1.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcursor1", rpm:"libxcursor1~1.1.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxext", rpm:"libxext~1.3.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxext6", rpm:"libxext6~1.3.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxext6-devel", rpm:"libxext6-devel~1.3.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxext6-static-devel", rpm:"libxext6-static-devel~1.3.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfixes", rpm:"libxfixes~5.0.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfixes3", rpm:"libxfixes3~5.0.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfixes3-devel", rpm:"libxfixes3-devel~5.0.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfixes3-static-devel", rpm:"libxfixes3-static-devel~5.0.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxi", rpm:"libxi~1.6.2.901~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxi-devel", rpm:"libxi-devel~1.6.2.901~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxi-static-devel", rpm:"libxi-static-devel~1.6.2.901~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxi6", rpm:"libxi6~1.6.2.901~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxinerama", rpm:"libxinerama~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxinerama1", rpm:"libxinerama1~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxinerama1-devel", rpm:"libxinerama1-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxinerama1-static-devel", rpm:"libxinerama1-static-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxp", rpm:"libxp~1.0.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxp-devel", rpm:"libxp-devel~1.0.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxp-static-devel", rpm:"libxp-static-devel~1.0.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxp6", rpm:"libxp6~1.0.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrandr", rpm:"libxrandr~1.4.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrandr2", rpm:"libxrandr2~1.4.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrandr2-devel", rpm:"libxrandr2-devel~1.4.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrandr2-static-devel", rpm:"libxrandr2-static-devel~1.4.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrender", rpm:"libxrender~0.9.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrender1", rpm:"libxrender1~0.9.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrender1-devel", rpm:"libxrender1-devel~0.9.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrender1-static-devel", rpm:"libxrender1-static-devel~0.9.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxres", rpm:"libxres~1.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxres1", rpm:"libxres1~1.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxres1-devel", rpm:"libxres1-devel~1.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxres1-static-devel", rpm:"libxres1-static-devel~1.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxt", rpm:"libxt~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxt-devel", rpm:"libxt-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxt-static-devel", rpm:"libxt-static-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxt6", rpm:"libxt6~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxtst", rpm:"libxtst~1.2.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxtst6", rpm:"libxtst6~1.2.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxtst6-devel", rpm:"libxtst6-devel~1.2.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxtst6-static-devel", rpm:"libxtst6-static-devel~1.2.2~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxv", rpm:"libxv~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxv1", rpm:"libxv1~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxv1-devel", rpm:"libxv1-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxv1-static-devel", rpm:"libxv1-static-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxvmc", rpm:"libxvmc~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxvmc1", rpm:"libxvmc1~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxvmc1-devel", rpm:"libxvmc1-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxvmc1-static-devel", rpm:"libxvmc1-static-devel~1.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86dga", rpm:"libxxf86dga~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86dga-devel", rpm:"libxxf86dga-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86dga-static-devel", rpm:"libxxf86dga-static-devel~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86dga1", rpm:"libxxf86dga1~1.1.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86vm", rpm:"libxxf86vm~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86vm-devel", rpm:"libxxf86vm-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86vm-static-devel", rpm:"libxxf86vm-static-devel~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxxf86vm1", rpm:"libxxf86vm1~1.1.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-common-devel", rpm:"mesa-common-devel~9.1.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-common-devel", rpm:"mesa-common-devel~9.1.3~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-openchrome", rpm:"x11-driver-video-openchrome~0.3.3~1.mga3", rls:"MAGEIA3"))) {
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
