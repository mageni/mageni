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
  script_oid("1.3.6.1.4.1.25623.1.0.853952");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2018-20340", "CVE-2019-9578");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:05:13 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for libu2f-host (openSUSE-SU-2021:1755-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1755-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/W6NOI7O3I53SFL6DVLZH5VWF6EO4AISA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libu2f-host'
  package(s) announced via the openSUSE-SU-2021:1755-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libu2f-host fixes the following issues:

     This update ships the u2f-host package (jsc#ECO-3687 bsc#1184648)

     Version 1.1.10 (released 2019-05-15)

  - Add new devices to udev rules.

  - Fix a potentially uninitialized buffer (CVE-2019-9578, bsc#1128140)

     Version 1.1.9 (released 2019-03-06)

  - Fix CID copying from the init response, which broke compatibility with
       some devices.

     Version 1.1.8 (released 2019-03-05)

  - Add udev rules

  - Drop 70-old-u2f.rules and use 70-u2f.rules for everything

  - Use a random nonce for setting up CID to prevent fingerprinting

  - CVE-2019-9578: Parse the response to init in a more stable way to
       prevent leakage of uninitialized stack memory back to the device
       (bsc#1128140).

     Version 1.1.7 (released 2019-01-08)

  - Fix for trusting length from device in device init.

  - Fix for buffer overflow when receiving data from device. (YSA-2019-01,
       CVE-2018-20340, bsc#1124781)

  - Add udev rules for some new devices.

  - Add udev rule for Feitian ePass FIDO

  - Add a timeout to the register and authenticate actions.");

  script_tag(name:"affected", value:"'libu2f-host' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libu2f-host-debuginfo", rpm:"libu2f-host-debuginfo~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libu2f-host-debugsource", rpm:"libu2f-host-debugsource~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libu2f-host-devel", rpm:"libu2f-host-devel~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libu2f-host-doc", rpm:"libu2f-host-doc~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libu2f-host0", rpm:"libu2f-host0~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libu2f-host0-debuginfo", rpm:"libu2f-host0-debuginfo~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u2f-host", rpm:"u2f-host~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u2f-host-debuginfo", rpm:"u2f-host-debuginfo~1.1.10~3.9.1", rls:"openSUSELeap15.3"))) {
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