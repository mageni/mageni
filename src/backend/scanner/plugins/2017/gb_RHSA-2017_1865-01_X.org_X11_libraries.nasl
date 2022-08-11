###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_1865-01_X.org_X11_libraries.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for X.org X11 libraries RHSA-2017:1865-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871852");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:22 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2016-10164", "CVE-2017-2625", "CVE-2017-2626");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for X.org X11 libraries RHSA-2017:1865-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'X.org X11 libraries'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The X11 (Xorg) libraries provide library
  routines that are used within all X Window applications. The following packages
  have been upgraded to a later upstream version: libX11 (1.6.5), libXaw (1.0.13),
  libXdmcp (1.1.2), libXfixes (5.0.3), libXfont (1.5.2), libXi (1.7.9), libXpm
  (3.5.12), libXrandr (1.5.1), libXrender (0.9.10), libXt (1.1.5), libXtst
  (1.2.3), libXv (1.0.11), libXvMC (1.0.10), libXxf86vm (1.1.4), libdrm (2.4.74),
  libepoxy (1.3.1), libevdev (1.5.6), libfontenc (1.1.3), libvdpau (1.1.1),
  libwacom (0.24), libxcb (1.12), libxkbfile (1.0.9), mesa (17.0.1),
  mesa-private-llvm (3.9.1), xcb-proto (1.12), xkeyboard-config (2.20),
  xorg-x11-proto-devel (7.7). (BZ#1401667, BZ#1401668, BZ#1401669, BZ#1401670,
  BZ#1401671, BZ#1401672, BZ#1401673, BZ#1401675, BZ#1401676, BZ#1401677,
  BZ#1401678, BZ#1401679, BZ#1401680, BZ#1401681, BZ#1401682, BZ#1401683,
  BZ#1401685, BZ#1401690, BZ#1401752, BZ#1401753, BZ#1401754, BZ#1402560,
  BZ#1410477, BZ#1411390, BZ#1411392, BZ#1411393, BZ#1411452, BZ#1420224) Security
  Fix(es): * An integer overflow flaw leading to a heap-based buffer overflow was
  found in libXpm. An attacker could use this flaw to crash an application using
  libXpm via a specially crafted XPM file. (CVE-2016-10164) * It was discovered
  that libXdmcp used weak entropy to generate session keys. On a multi-user system
  using xdmcp, a local attacker could potentially use information available from
  the process list to brute force the key, allowing them to hijack other users'
  sessions. (CVE-2017-2625) * It was discovered that libICE used a weak entropy to
  generate keys. A local attacker could potentially use this flaw for session
  hijacking using the information available from the process list. (CVE-2017-2626)
  Red Hat would like to thank Eric Sesterhenn (X41 D-Sec GmbH) for reporting
  CVE-2017-2625 and CVE-2017-2626. Additional Changes: For detailed information on
  changes in this release, see the Red Hat Enterprise Linux 7.4 Release Notes
  linked from the References section.");
  script_tag(name:"affected", value:"X.org X11 libraries on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00008.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libX11-common", rpm:"libX11-common~1.6.5~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwacom-data", rpm:"libwacom-data~0.24~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xkeyboard-config", rpm:"xkeyboard-config~2.20~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-proto-devel", rpm:"xorg-x11-proto-devel~7.7~20.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libICE", rpm:"libICE~1.0.9~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libICE-debuginfo", rpm:"libICE-debuginfo~1.0.9~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libICE-devel", rpm:"libICE-devel~1.0.9~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libX11", rpm:"libX11~1.6.5~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libX11-debuginfo", rpm:"libX11-debuginfo~1.6.5~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXaw", rpm:"libXaw~1.0.13~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXaw-debuginfo", rpm:"libXaw-debuginfo~1.0.13~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXaw-devel", rpm:"libXaw-devel~1.0.13~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXcursor", rpm:"libXcursor~1.1.14~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXcursor-debuginfo", rpm:"libXcursor-debuginfo~1.1.14~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXcursor-devel", rpm:"libXcursor-devel~1.1.14~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXdmcp", rpm:"libXdmcp~1.1.2~6.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXdmcp-debuginfo", rpm:"libXdmcp-debuginfo~1.1.2~6.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfixes", rpm:"libXfixes~5.0.3~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfixes-debuginfo", rpm:"libXfixes-debuginfo~5.0.3~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfixes-devel", rpm:"libXfixes-devel~5.0.3~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.5.2~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.5.2~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont2", rpm:"libXfont2~2.0.1~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont2-debuginfo", rpm:"libXfont2-debuginfo~2.0.1~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXi", rpm:"libXi~1.7.9~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXi-debuginfo", rpm:"libXi-debuginfo~1.7.9~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXi-devel", rpm:"libXi-devel~1.7.9~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXpm", rpm:"libXpm~3.5.12~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXpm-debuginfo", rpm:"libXpm-debuginfo~3.5.12~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXpm-devel", rpm:"libXpm-devel~3.5.12~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrandr", rpm:"libXrandr~1.5.1~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrandr-debuginfo", rpm:"libXrandr-debuginfo~1.5.1~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrandr-devel", rpm:"libXrandr-devel~1.5.1~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrender", rpm:"libXrender~0.9.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrender-debuginfo", rpm:"libXrender-debuginfo~0.9.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrender-devel", rpm:"libXrender-devel~0.9.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXt", rpm:"libXt~1.1.5~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXt-debuginfo", rpm:"libXt-debuginfo~1.1.5~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXt-devel", rpm:"libXt-devel~1.1.5~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXtst", rpm:"libXtst~1.2.3~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXtst-debuginfo", rpm:"libXtst-debuginfo~1.2.3~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXtst-devel", rpm:"libXtst-devel~1.2.3~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXv", rpm:"libXv~1.0.11~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXv-debuginfo", rpm:"libXv-debuginfo~1.0.11~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXv-devel", rpm:"libXv-devel~1.0.11~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC", rpm:"libXvMC~1.0.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC-debuginfo", rpm:"libXvMC-debuginfo~1.0.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86vm", rpm:"libXxf86vm~1.1.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86vm-debuginfo", rpm:"libXxf86vm-debuginfo~1.1.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86vm-devel", rpm:"libXxf86vm-devel~1.1.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdrm", rpm:"libdrm~2.4.74~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdrm-debuginfo", rpm:"libdrm-debuginfo~2.4.74~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdrm-devel", rpm:"libdrm-devel~2.4.74~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libepoxy", rpm:"libepoxy~1.3.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libepoxy-debuginfo", rpm:"libepoxy-debuginfo~1.3.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libepoxy-devel", rpm:"libepoxy-devel~1.3.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libevdev", rpm:"libevdev~1.5.6~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libevdev-debuginfo", rpm:"libevdev-debuginfo~1.5.6~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfontenc", rpm:"libfontenc~1.1.3~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfontenc-debuginfo", rpm:"libfontenc-debuginfo~1.1.3~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libinput", rpm:"libinput~1.6.3~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libinput-debuginfo", rpm:"libinput-debuginfo~1.6.3~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau", rpm:"libvdpau~1.1.1~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau-debuginfo", rpm:"libvdpau-debuginfo~1.1.1~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwacom", rpm:"libwacom~0.24~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwacom-debuginfo", rpm:"libwacom-debuginfo~0.24~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcb", rpm:"libxcb~1.12~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcb-debuginfo", rpm:"libxcb-debuginfo~1.12~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.12~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon", rpm:"libxkbcommon~0.7.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-debuginfo", rpm:"libxkbcommon-debuginfo~0.7.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-x11", rpm:"libxkbcommon-x11~0.7.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbfile", rpm:"libxkbfile~1.0.9~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbfile-debuginfo", rpm:"libxkbfile-debuginfo~1.0.9~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbfile-devel", rpm:"libxkbfile-devel~1.0.9~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-debuginfo", rpm:"mesa-debuginfo~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-dri-drivers", rpm:"mesa-dri-drivers~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-filesystem", rpm:"mesa-filesystem~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libEGL", rpm:"mesa-libEGL~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libEGL-devel", rpm:"mesa-libEGL-devel~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGL", rpm:"mesa-libGL~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGL-devel", rpm:"mesa-libGL-devel~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGLES", rpm:"mesa-libGLES~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libgbm", rpm:"mesa-libgbm~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libglapi", rpm:"mesa-libglapi~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libxatracker", rpm:"mesa-libxatracker~17.0.1~6.20170307.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-private-llvm", rpm:"mesa-private-llvm~3.9.1~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-private-llvm-debuginfo", rpm:"mesa-private-llvm-debuginfo~3.9.1~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}