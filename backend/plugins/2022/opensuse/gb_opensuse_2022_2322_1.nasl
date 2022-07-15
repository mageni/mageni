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
  script_oid("1.3.6.1.4.1.25623.1.0.854796");
  script_version("2022-07-13T10:13:19+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-13 10:13:19 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-08 01:01:42 +0000 (Fri, 08 Jul 2022)");
  script_name("openSUSE: Security Advisory for fwupd (SUSE-SU-2022:2322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2322-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XLSFQ3JYDSACCJ5OK7OVNLBRUSK6USFY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fwupd'
  package(s) announced via the SUSE-SU-2022:2322-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of fwupd fixes the following issue:

  - rebuild with new secure boot key due to grub2 boothole 3 issues
       (bsc#1198581)");

  script_tag(name:"affected", value:"'fwupd' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"fwupdtpmevlog", rpm:"fwupdtpmevlog~1.5.8~150300.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdtpmevlog-debuginfo", rpm:"fwupdtpmevlog-debuginfo~1.5.8~150300.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupdplugin1", rpm:"libfwupdplugin1~1.5.8~150300.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupdplugin1-debuginfo", rpm:"libfwupdplugin1-debuginfo~1.5.8~150300.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"dfu-tool", rpm:"dfu-tool~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dfu-tool-debuginfo", rpm:"dfu-tool-debuginfo~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd", rpm:"fwupd~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-debuginfo", rpm:"fwupd-debuginfo~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-debugsource", rpm:"fwupd-debugsource~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-devel", rpm:"fwupd-devel~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdtpmevlog", rpm:"fwupdtpmevlog~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupdtpmevlog-debuginfo", rpm:"fwupdtpmevlog-debuginfo~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupd2", rpm:"libfwupd2~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupd2-debuginfo", rpm:"libfwupd2-debuginfo~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupdplugin1", rpm:"libfwupdplugin1~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupdplugin1-debuginfo", rpm:"libfwupdplugin1-debuginfo~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Fwupd-2_0", rpm:"typelib-1_0-Fwupd-2_0~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-FwupdPlugin-1_0", rpm:"typelib-1_0-FwupdPlugin-1_0~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-lang", rpm:"fwupd-lang~1.5.8~150300.3.5.1", rls:"openSUSELeap15.3"))) {
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