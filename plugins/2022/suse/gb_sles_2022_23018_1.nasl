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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.23018.1");
  script_cve_id("CVE-2020-14370", "CVE-2020-15157", "CVE-2021-20199", "CVE-2021-20291", "CVE-2021-3602", "CVE-2021-4024", "CVE-2021-41190");
  script_tag(name:"creation_date", value:"2022-03-05 04:11:51 +0000 (Sat, 05 Mar 2022)");
  script_version("2022-03-08T09:48:19+0000");
  script_tag(name:"last_modification", value:"2022-03-08 11:27:32 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-09 17:15:00 +0000 (Fri, 09 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:23018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:23018-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-202223018-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conmon, libcontainers-common, libseccomp, podman' package(s) announced via the SUSE-SU-2022:23018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for conmon, libcontainers-common, libseccomp, podman fixes the following issues:

podman was updated to 3.4.4.

Security issues fixed:


fix CVE-2021-41190 [bsc#1193273], opencontainers: OCI manifest and index
 parsing confusion

fix CVE-2021-4024 [bsc#1193166], podman machine spawns gvproxy with
 port binded to all IPs

fix CVE-2021-20199 [bsc#1181640], Remote traffic to rootless containers
 is seen as originating from localhost

Add: Provides: podman:/usr/bin/podman-remote subpackage for a clearer
 upgrade path from podman < 3.1.2

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

Update to version 3.4.3:

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
 - Fixed a bug where the podman logs -f command would, when using the
 journald logs backend, exit immediately if the container had
 previously been restarted (#12263).
 - Fixed a bug where, in containers on VMs created by podman machine,
 the host.containers.internal name pointed to the VM, not the host
 system (#11642).
 - Fixed a bug where containers and pods created by the podman play
 kube command in VMs managed by podman machine would not
 automatically forward ports from the host machine (#12248).
 - Fixed a bug where podman machine init would fail on OS X when GNU
 Coreutils was installed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'conmon, libcontainers-common, libseccomp, podman' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Containers 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common", rpm:"libcontainers-common~20210626~150300.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-debugsource", rpm:"libseccomp-debugsource~2.5.3~150300.10.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-devel", rpm:"libseccomp-devel~2.5.3~150300.10.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2", rpm:"libseccomp2~2.5.3~150300.10.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-debuginfo", rpm:"libseccomp2-debuginfo~2.5.3~150300.10.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.0.30~150300.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.0.30~150300.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~3.4.4~150300.9.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~3.4.4~150300.9.3.2", rls:"SLES15.0SP3"))) {
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
