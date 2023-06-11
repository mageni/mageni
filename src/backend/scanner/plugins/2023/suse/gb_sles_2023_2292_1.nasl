# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2292.1");
  script_cve_id("CVE-2021-25749", "CVE-2022-3162", "CVE-2022-3294");
  script_tag(name:"creation_date", value:"2023-05-29 04:23:31 +0000 (Mon, 29 May 2023)");
  script_version("2023-05-30T09:08:51+0000");
  script_tag(name:"last_modification", value:"2023-05-30 09:08:51 +0000 (Tue, 30 May 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 00:58:00 +0000 (Thu, 09 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2292-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232292-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.23' package(s) announced via the SUSE-SU-2023:2292-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.23 fixes the following issues:


add kubernetes1.18-client-common as conflicts with kubernetes-client-bash-completion


Split individual completions into separate packages


Update to version 1.23.17:

releng: Update images, dependencies and version to Go 1.19.6 Update golang.org/x/net to v0.7.0 Pin golang.org/x/net to v0.4.0 add scale test for probes use custom dialer for http probes use custom dialer for tcp probes add custom dialer optimized for probes egress_selector: prevent goroutines leak on connect() step.
tls.Dial() validates hostname, no need to do that manually Fix issue that Audit Server could not correctly encode DeleteOption Do not include scheduler name in the preemption event message Do not leak cross namespace pod metadata in preemption events pkg/controller/job: re-honor exponential backoff releng: Update images, dependencies and version to Go 1.19.5 Bump Konnectivity to v0.0.35 Improve vendor verification works for each staging repo Update to go1.19 Adjust for os/exec changes in 1.19 Update golangci-lint to 1.46.2 and fix errors Match go1.17 defaults for SHA-1 and GC update golangci-lint to 1.45.0 kubelet: make the image pull time more accurate in event change k8s.gcr.io/pause to registry.k8s.io/pause use etcd 3.5.6-0 after promotion changelog: CVE-2022-3294 and CVE-2022-3162 were fixed in v1.23.14 Add CVE-2021-25749 to CHANGELOG-1.23.md Add CVE-2022-3294 to CHANGELOG-1.23.md kubeadm: use registry.k8s.io instead of k8s.gcr.io etcd: Updated to v3.5.5 Bump konnectivity network proxy to v0.0.33. Includes a couple bug fixes for better handling of dial failures. Agent & Server include numerous other fixes.
kubeadm: allow RSA and ECDSA format keys in preflight check Fixes kubelet log compression on Windows Reduce default gzip compression level from 4 to 1 in apiserver exec auth: support TLS config caching Marshal MicroTime to json and proto at the same precision Windows: ensure runAsNonRoot does case-insensitive comparison on user name update structured-merge-diff to 4.2.3 Add rate limiting when calling STS assume role API Fixing issue in generatePodSandboxWindowsConfig for hostProcess containers by where pod sandbox won't have HostProcess bit set if pod does not have a security context but containers specify HostProcess.");

  script_tag(name:"affected", value:"'kubernetes1.23' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client", rpm:"kubernetes1.23-client~1.23.17~150300.7.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-common", rpm:"kubernetes1.23-client-common~1.23.17~150300.7.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-debuginfo", rpm:"kubernetes1.23-client-debuginfo~1.23.17~150300.7.6.1", rls:"SLES15.0SP3"))) {
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
