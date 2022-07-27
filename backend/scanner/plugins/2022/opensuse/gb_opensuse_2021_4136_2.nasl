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
  script_oid("1.3.6.1.4.1.25623.1.0.854497");
  script_version("2022-02-22T06:48:08+0000");
  script_cve_id("CVE-2021-4009", "CVE-2021-4010", "CVE-2021-4011");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-22 02:01:32 +0000 (Tue, 22 Feb 2022)");
  script_name("openSUSE: Security Advisory for xorg-x11-server (openSUSE-SU-2021:4136-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:4136-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T3CAZLVDCJF5S7L74XKKD3UFRYGUKDJ6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the openSUSE-SU-2021:4136-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-server fixes the following issues:

  - CVE-2021-4009: The handler for the CreatePointerBarrier request of the
       XFixes extension does not properly validate the request length leading
       to out of bounds memory write. (bsc#1190487)

  - CVE-2021-4010: The handler for the Suspend request of the Screen Saver
       extension does not properly validate the request length leading to out
       of bounds memory write. (bsc#1190488)

  - CVE-2021-4011: The handlers for the RecordCreateContext and
       RecordRegisterClients requests of the Record extension do not properly
       validate the request length leading to out of bounds memory write.
       (bsc#1190489)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-wayland", rpm:"xorg-x11-server-wayland~1.20.3~22.5.42.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-wayland-debuginfo", rpm:"xorg-x11-server-wayland-debuginfo~1.20.3~22.5.42.1", rls:"openSUSELeap15.4"))) {
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