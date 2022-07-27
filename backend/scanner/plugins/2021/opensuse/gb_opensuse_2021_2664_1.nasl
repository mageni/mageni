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
  script_oid("1.3.6.1.4.1.25623.1.0.854063");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-29622");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 03:01:33 +0000 (Fri, 13 Aug 2021)");
  script_name("openSUSE: Security Advisory for golang-github-prometheus-prometheus (openSUSE-SU-2021:2664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2664-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/W3KPAMVZLF5BC7A6E5Z2QSNUUFHXGK6B");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-prometheus'
  package(s) announced via the openSUSE-SU-2021:2664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for golang-github-prometheus-prometheus fixes the following
     issues:

  - Provide and reload firewalld configuration only for:
       + openSUSE Leap 15.0, 15.1, 15.2
       + SUSE SLE15, SLE15 SP1, SLE15 SP2

  - Upgrade to upstream version 2.27.1 (jsc#SLE-18254)
       + Bugfix:

  * SECURITY: Fix arbitrary redirects under the /new endpoint
          (CVE-2021-29622, bsc#1186242)
       + Features:

  * Promtool: Retroactive rule evaluation functionality. #7675

  * Configuration: Environment variable expansion for external labels.
           Behind --enable-feature=expand-external-labels flag. #8649

  * TSDB: Add a flag(--storage.tsdb.max-block-chunk-segment-size) to
           control the max chunks file size of the blocks for small Prometheus
           instances.

  * UI: Add a dark theme. #8604

  * AWS Lightsail Discovery: Add AWS Lightsail Discovery. #8693

  * Docker Discovery: Add Docker Service Discovery. #8629

  * OAuth: Allow OAuth 2.0 to be used anywhere an HTTP client is used.
           #8761

  * Remote Write: Send exemplars via remote write. Experimental and
           disabled by default. #8296
       + Enhancements:

  * Digital Ocean Discovery: Add __meta_digitalocean_vpc label. #8642

  * Scaleway Discovery: Read Scaleway secret from a file. #8643

  * Scrape: Add configurable limits for label size and count. #8777

  * UI: Add 16w and 26w time range steps. #8656

  * Templating: Enable parsing strings in humanize functions. #8682
       + Bugfixes:

  * UI: Provide errors instead of blank page on TSDB Status Page. #8654
           #8659

  * TSDB: Do not panic when writing very large records to the WAL. #8790

  * TSDB: Avoid panic when mapped memory is referenced after the file is
           closed. #8723

  * Scaleway Discovery: Fix nil pointer dereference. #8737

  * Consul Discovery: Restart no longer required after config update
           with no targets. #8766

  - Add tarball with vendor modules and web assets

  - Uyuni: Read formula data from exporters map

  - Uyuni: Add support for TLS targets

  - Upgrade to upstream version 2.26.0
       + Changes

  * Alerting: Using Alertmanager v2 API by default. #8626

  * Prometheus/Promtool: Binaries are now printing help and usage to
           stdout instead of stderr. #8542
       + Features

  * Remote: Add support for AWS SigV4 auth method for remote_write. #8509

  * PromQL: Allow negative offsets. Behind
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'golang-github-prometheus-prometheus' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.27.1~3.8.1", rls:"openSUSELeap15.3"))) {
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
