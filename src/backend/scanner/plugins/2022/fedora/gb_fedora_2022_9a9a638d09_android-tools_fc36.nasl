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
  script_oid("1.3.6.1.4.1.25623.1.0.822751");
  script_version("2022-11-17T05:30:14+0000");
  script_cve_id("CVE-2022-20128", "CVE-2022-3168", "CVE-2022-1996", "CVE-2022-24675", "CVE-2022-28327", "CVE-2022-27191", "CVE-2022-29526", "CVE-2022-30629");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-11-17 05:30:14 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-14 02:13:05 +0000 (Mon, 14 Nov 2022)");
  script_name("Fedora: Security Advisory for android-tools (FEDORA-2022-9a9a638d09)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-9a9a638d09");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KRD4P3VOEG62HK6DIKWYFVKLS5CLIZ2T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'android-tools'
  package(s) announced via the FEDORA-2022-9a9a638d09 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Android Debug Bridge (ADB) is used to:

  - keep track of all Android devices and emulators instances
  connected to or running on a given host developer machine

  - implement various control commands (e.g. 'adb shell', 'adb pull',
etc.)
  for the benefit of clients (command-line users, or helper programs like
  DDMS). These commands are what is called a &#39, service&#39, in ADB.

Fastboot is used to manipulate the flash partitions of the Android phone.
It can also boot the phone using a kernel image or root filesystem image
which reside on the host machine rather than in the phone flash.
In order to use it, it is important to understand the flash partition
layout for the phone.
The fastboot program works in conjunction with firmware on the phone
to read and write the flash partitions. It needs the same USB device
setup between the host and the target phone as adb.");

  script_tag(name:"affected", value:"'android-tools' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"android-tools", rpm:"android-tools~33.0.3p1~1.fc36", rls:"FC36"))) {
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