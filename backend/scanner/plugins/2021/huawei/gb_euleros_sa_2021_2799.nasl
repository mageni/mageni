# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2799");
  script_cve_id("CVE-2021-41133");
  script_tag(name:"creation_date", value:"2021-12-26 03:23:15 +0000 (Sun, 26 Dec 2021)");
  script_version("2022-01-03T09:39:10+0000");
  script_tag(name:"last_modification", value:"2022-01-03 09:39:10 +0000 (Mon, 03 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 19:57:00 +0000 (Fri, 15 Oct 2021)");

  script_name("Huawei EulerOS: Security Advisory for flatpak (EulerOS-SA-2021-2799)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2799");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2799");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'flatpak' package(s) announced via the EulerOS-SA-2021-2799 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In versions prior to 1.10.4 and 1.12.0, Flatpak apps with direct access to AF_UNIX sockets such as those used by Wayland, Pipewire or pipewire-pulse can trick portals and other host-OS services into treating the Flatpak app as though it was an ordinary, non-sandboxed host-OS process. They can do this by manipulating the VFS using recent mount-related syscalls that are not blocked by Flatpak's denylist seccomp filter, in order to substitute a crafted `/.flatpak-info` or make that file disappear entirely. Flatpak apps that act as clients for AF_UNIX sockets such as those used by Wayland, Pipewire or pipewire-pulse can escalate the privileges that the corresponding services will believe the Flatpak app has. Note that protocols that operate entirely over the D-Bus session bus (user bus), system bus or accessibility bus are not affected by this. This is due to the use of a proxy process `xdg-dbus-proxy`, whose VFS cannot be manipulated by the Flatpak app, when interacting with these buses. Patches exist for versions 1.10.4 and 1.12.0, and as of time of publication, a patch for version 1.8.2 is being planned. There are no workarounds aside from upgrading to a patched version.(CVE-2021-41133)");

  script_tag(name:"affected", value:"'flatpak' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.0.3~1.h6.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-libs", rpm:"flatpak-libs~1.0.3~1.h6.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
