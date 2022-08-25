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
  script_oid("1.3.6.1.4.1.25623.1.0.854906");
  script_version("2022-08-22T10:11:10+0000");
  script_cve_id("CVE-2022-1227", "CVE-2022-21698", "CVE-2022-27191");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 14:52:00 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2022-08-18 01:05:06 +0000 (Thu, 18 Aug 2022)");
  script_name("openSUSE: Security Advisory for podman (SUSE-SU-2022:2834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2834-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3XQI3JGSN3QUR2TTD5PKGO62TDA7VS3I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman'
  package(s) announced via the SUSE-SU-2022:2834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:
  Updated to version 3.4.7:

  - CVE-2022-1227: Fixed an issue that could allow an attacker to publish a
       malicious image to a public registry and run arbitrary code in the
       victim's context via the 'podman top' command (bsc#1182428).

  - CVE-2022-27191: Fixed a potential crash via SSH under specific
       configurations (bsc#1197284).

  - CVE-2022-21698: Fixed a potential denial of service that affected
       servers that used Prometheus instrumentation (bsc#1196338).");

  script_tag(name:"affected", value:"'podman' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~3.4.7~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~3.4.7~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~3.4.7~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~3.4.7~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~3.4.7~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~3.4.7~150400.4.3.1", rls:"openSUSELeap15.4"))) {
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