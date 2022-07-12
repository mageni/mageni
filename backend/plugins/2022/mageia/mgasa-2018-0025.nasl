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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0025");
  script_cve_id("CVE-2017-5209", "CVE-2017-5545", "CVE-2017-5834", "CVE-2017-5835", "CVE-2017-5836", "CVE-2017-6435", "CVE-2017-6436", "CVE-2017-6437", "CVE-2017-6438", "CVE-2017-6439", "CVE-2017-6440", "CVE-2017-7982");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-02 10:15:00 +0000 (Thu, 02 Apr 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0025");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0025.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20232");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-05/msg00094.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-08/msg00082.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gvfs, ifuse, kodi, libgpod, libimobiledevice, libplist, upower, usbmuxd' package(s) announced via the MGASA-2018-0025 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The base64decode function in libplist allowed attackers to obtain
sensitive information from process memory or cause a denial of
service (buffer over-read) via split encoded Apple Property List data
(CVE-2017-5209).

The main function in plistutil.c in libimobiledevice libplist allowed
attackers to obtain sensitive information from process memory or cause a
denial of service (buffer over-read) via Apple Property List data that is
too short (CVE-2017-5545).

A heap-buffer overflow in parse_dict_node could cause a segmentation fault
(CVE-2017-5834).

Malicious crafted file could cause libplist to allocate large amounts of
memory and consume lots of CPU because of a memory allocation error
(CVE-2017-5835).

A type inconsistency in bplist.c could cause the application to crash
(CVE-2017-5836).

Crafted plist file could lead to Heap-buffer overflow (CVE-2017-6435).

Integer overflow in parse_string_node (CVE-2017-6436).

The base64encode function in base64.c allows local users to cause denial
of service (out-of-bounds read) via a crafted plist file (CVE-2017-6437).

Heap-based buffer overflow in the parse_unicode_node function
(CVE-2017-6438).

Heap-based buffer overflow in the parse_string_node function
(CVE-2017-6439).

Ensure that sanity checks work on 32-bit platforms (CVE-2017-6440).

Add some safety checks, backported from upstream (CVE-2017-7982).

The gvfs, ifuse, kodi, libgpod, libimobiledevice, upower, and usbmuxd
packages have been rebuilt for the updated libplist.");

  script_tag(name:"affected", value:"'gvfs, ifuse, kodi, libgpod, libimobiledevice, libplist, upower, usbmuxd' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-archive", rpm:"gvfs-archive~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-devel", rpm:"gvfs-devel~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-goa", rpm:"gvfs-goa~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-gphoto2", rpm:"gvfs-gphoto2~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-iphone", rpm:"gvfs-iphone~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-mtp", rpm:"gvfs-mtp~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-smb", rpm:"gvfs-smb~1.22.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ifuse", rpm:"ifuse~1.1.3~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kodi", rpm:"kodi~14.0~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kodi-devel", rpm:"kodi-devel~14.0~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kodi-eventclient-j2me", rpm:"kodi-eventclient-j2me~14.0~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kodi-eventclient-kodi-send", rpm:"kodi-eventclient-kodi-send~14.0~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kodi-eventclient-ps3", rpm:"kodi-eventclient-ps3~14.0~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kodi-eventclient-wiiremote", rpm:"kodi-eventclient-wiiremote~14.0~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kodi-eventclients-common", rpm:"kodi-eventclients-common~14.0~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpod-devel", rpm:"lib64gpod-devel~0.8.3~8.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpod4", rpm:"lib64gpod4~0.8.3~8.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64imobiledevice-devel", rpm:"lib64imobiledevice-devel~1.1.6~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64imobiledevice4", rpm:"lib64imobiledevice4~1.1.6~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plist++-devel", rpm:"lib64plist++-devel~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plist++3", rpm:"lib64plist++3~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plist-devel", rpm:"lib64plist-devel~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plist3", rpm:"lib64plist3~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64upower-gir1.0", rpm:"lib64upower-gir1.0~0.99.2~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64upower-glib-devel", rpm:"lib64upower-glib-devel~0.99.2~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64upower-glib3", rpm:"lib64upower-glib3~0.99.2~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64usbmuxd-devel", rpm:"lib64usbmuxd-devel~1.0.9~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64usbmuxd2", rpm:"lib64usbmuxd2~1.0.9~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpod", rpm:"libgpod~0.8.3~8.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpod-devel", rpm:"libgpod-devel~0.8.3~8.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpod-sharp", rpm:"libgpod-sharp~0.8.3~8.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpod4", rpm:"libgpod4~0.8.3~8.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimobiledevice", rpm:"libimobiledevice~1.1.6~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimobiledevice-devel", rpm:"libimobiledevice-devel~1.1.6~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimobiledevice4", rpm:"libimobiledevice4~1.1.6~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplist++-devel", rpm:"libplist++-devel~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplist++3", rpm:"libplist++3~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplist", rpm:"libplist~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplist-devel", rpm:"libplist-devel~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplist3", rpm:"libplist3~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupower-gir1.0", rpm:"libupower-gir1.0~0.99.2~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupower-glib-devel", rpm:"libupower-glib-devel~0.99.2~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupower-glib3", rpm:"libupower-glib3~0.99.2~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbmuxd-devel", rpm:"libusbmuxd-devel~1.0.9~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbmuxd2", rpm:"libusbmuxd2~1.0.9~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gpod", rpm:"python-gpod~0.8.3~8.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-imobiledevice", rpm:"python-imobiledevice~1.1.6~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-plist", rpm:"python-plist~1.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"upower", rpm:"upower~0.99.2~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usbmuxd", rpm:"usbmuxd~1.0.9~6.2.mga5", rls:"MAGEIA5"))) {
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
