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
  script_oid("1.3.6.1.4.1.25623.1.0.854543");
  script_version("2022-03-15T08:14:31+0000");
  script_cve_id("CVE-2020-14370", "CVE-2020-15157", "CVE-2021-20199", "CVE-2021-20291", "CVE-2021-3602", "CVE-2021-4024", "CVE-2021-41190");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-05 02:02:17 +0000 (Sat, 05 Mar 2022)");
  script_name("openSUSE: Security Advisory for conmon, (openSUSE-SU-2022:23018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:23018-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5BA2TLW7O5ZURGQUAQUH4HD5SQYNDDZ6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conmon, '
  package(s) announced via the openSUSE-SU-2022:23018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for conmon, libcontainers-common, libseccomp, podman fixes the
     following issues:
  podman was updated to 3.4.4.
  Security issues fixed:

  - fix CVE-2021-41190 [bsc#1193273], opencontainers: OCI manifest and index
       parsing confusion

  - fix CVE-2021-4024  [bsc#1193166], podman machine spawns gvproxy with
       port binded to all IPs

  - fix CVE-2021-20199 [bsc#1181640], Remote traffic to rootless containers
       is seen as originating from localhost

  - Add: Provides: podman:/usr/bin/podman-remote subpackage for a clearer
       upgrade path from podman   3.1.2
  Update to version 3.4.4:

  * Bugfixes

  - Fixed a bug where the podman exec command would, under some
           circumstances, print a warning message about failing to move conmon
           to the appropriate cgroup (#12535).

  - Fixed a bug where named volumes created as part of container
           creation (e.g. podman run --volume avolume:/a/mountpoint or similar)
           would be mounted with incorrect permissions (#12523).

  - Fixed a bug where the podman-remote create and podman-remote run
           commands did not properly handle the --entrypoint='' option (to
           clear the container's entrypoint) (#12521).

  - Update to version 3.4.3:

  * Security

  - This release addresses CVE-2021-4024, where the podman machine
           command opened the gvproxy API (used to forward ports to podman
           machine VMs) to the public internet on port 7777.

  - This release addresses CVE-2021-41190, where incomplete
           specification of behavior regarding image manifests could lead to
           inconsistent decoding on different clients.

  * Features

  - The --secret type=mount option to podman create and podman run
           supports a new option, target=, which specifies where in the
           container the secret will be mounted (#12287).

  * Bugfixes

  - Fixed a bug where rootless Podman would occasionally print warning
           messages about failing to move the pause process to a new cgroup
           (#12065).

  - Fixed a bug where the podman run and podman create commands would,
           when pulling images, still require TLS even with registries set to
           Insecure via config file (#11933).

  - Fixed a bug where the podman generate systemd command generated
           units that depended on multi-user.target, which has been removed
           from some distributions (#12438).

  - Fixed a bug where Podman could not run containers with images that
           had /etc/ as a symlink (#12189).

  - Fixed a b ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'conmon, ' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.0.30~150300.8.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.0.30~150300.8.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-debugsource", rpm:"libseccomp-debugsource~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-devel", rpm:"libseccomp-devel~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-tools", rpm:"libseccomp-tools~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-tools-debuginfo", rpm:"libseccomp-tools-debuginfo~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2", rpm:"libseccomp2~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-debuginfo", rpm:"libseccomp2-debuginfo~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~3.4.4~150300.9.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit", rpm:"libseccomp2-32bit~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit-debuginfo", rpm:"libseccomp2-32bit-debuginfo~2.5.3~150300.10.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common-20210626", rpm:"libcontainers-common-20210626~150300.8.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~3.4.4~150300.9.3.2", rls:"openSUSELeap15.3"))) {
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
