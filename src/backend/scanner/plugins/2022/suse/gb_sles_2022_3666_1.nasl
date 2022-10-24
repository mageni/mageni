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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3666.1");
  script_cve_id("CVE-2022-1996", "CVE-2022-36055");
  script_tag(name:"creation_date", value:"2022-10-20 04:46:48 +0000 (Thu, 20 Oct 2022)");
  script_version("2022-10-20T10:12:23+0000");
  script_tag(name:"last_modification", value:"2022-10-20 10:12:23 +0000 (Thu, 20 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:00 +0000 (Thu, 16 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3666-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3666-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223666-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'helm' package(s) announced via the SUSE-SU-2022:3666-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for helm fixes the following issues:

helm was updated to version 3.9.4:

CVE-2022-36055: Fixed denial of service through string value parsing
 (bsc#1203054).

Updating the certificates used for testing

Updating index handling

helm was updated to version 3.9.3:

CVE-2022-1996: Updated kube-openapi to fix an issue that could result in
 a CORS protection bypass (bsc#1200528).

Fix missing array length check on release

helm was updated to version 3.9.2:

Update of the circleci image

helm was updated to version 3.9.1:

Update to support Kubernetes 1.24.2

Improve logging and safety of statefulSetReady

Make token caching an opt-in feature

Bump github.com/lib/pq from 1.10.5 to 1.10.6

Bump github.com/Masterminds/squirrel from 1.5.2 to 1.5.3

helm was updated to version 3.9.0:

Added a --quiet flag to helm lint

Added a --post-renderer-args flag to support arguments being passed to
 the post renderer

Added more checks during the signing process

Updated to add Kubernetes 1.24 support

helm was updated to version 3.8.2:

Bump oras.land/oras-go from 1.1.0 to 1.1.1

Fixing downloader plugin error handling

Simplify testdata charts

Simplify testdata charts

Add tests for multi-level dependencies.

Fix value precedence

Bumping Kubernetes package versions

Updating vcs to latest version

Dont modify provided transport

Pass http getter as pointer in tests

Add docs block

Add transport option and tests

Reuse http transport

Updating Kubernetes libs to 0.23.4 (latest)

fix: remove deadcode

fix: helm package tests

fix: helm package with dependency update for charts with OCI dependencies

Fix typo Unset the env var before func return in Unit Test

add legal name check

maint: fix syntax error in deploy.sh

linting issue fixed

only apply overwrite if version is canary

overwrite flag added to az storage blob upload-batch

Avoid querying for OCI tags can explicit version provided in chart
 dependencies

Management of bearer tokens for tag listing

Updating Kubernetes packages to 1.23.3

refactor: use `os.ReadDir` for lightweight directory reading

Add IngressClass to manifests to be (un)installed

feat(comp): Shell completion for OCI

Fix install memory/goroutine leak");

  script_tag(name:"affected", value:"'helm' package(s) on SUSE Linux Enterprise Module for Containers 15-SP3, SUSE Linux Enterprise Module for Containers 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"helm", rpm:"helm~3.9.4~150000.1.10.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-bash-completion", rpm:"helm-bash-completion~3.9.4~150000.1.10.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-debuginfo", rpm:"helm-debuginfo~3.9.4~150000.1.10.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-zsh-completion", rpm:"helm-zsh-completion~3.9.4~150000.1.10.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-fish-completion", rpm:"helm-fish-completion~3.9.4~150000.1.10.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"helm", rpm:"helm~3.9.4~150000.1.10.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-bash-completion", rpm:"helm-bash-completion~3.9.4~150000.1.10.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-debuginfo", rpm:"helm-debuginfo~3.9.4~150000.1.10.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-zsh-completion", rpm:"helm-zsh-completion~3.9.4~150000.1.10.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-fish-completion", rpm:"helm-fish-completion~3.9.4~150000.1.10.3", rls:"SLES15.0SP4"))) {
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
