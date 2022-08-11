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
  script_oid("1.3.6.1.4.1.25623.1.0.854073");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-27962", "CVE-2021-28146", "CVE-2021-28147", "CVE-2021-28148", "CVE-2021-29622");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-18 03:02:57 +0000 (Wed, 18 Aug 2021)");
  script_name("openSUSE: Security Advisory for SUSE (openSUSE-SU-2021:1162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1162-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2SW3762PL7VO3NVHZJOSVYMKION77NYI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE'
  package(s) announced via the openSUSE-SU-2021:1162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

     ansible:

  - The support level for ansible is l2, not l3

     dracut-saltboot:

  - Force installation of libexpat.so.1 (bsc#1188846)

  - Use kernel parameters from PXE formula also for local boot

     golang-github-prometheus-prometheus:

  - Provide and reload firewalld configuration only for:
       + openSUSE Leap 15.0, 15.1, 15.2
       + SUSE Linux Enterprise 15, 15 SP1, 15 SP2

  - Upgrade to upstream version 2.27.1 (jsc#SLE-18254)
       + Bugfix:

  * SECURITY: Fix arbitrary redirects under the /new endpoint
          (CVE-2021-29622, bsc#1186242)

  * UI: Provide errors instead of blank page on TSDB Status Page. #8654
          #8659

  * TSDB: Do not panic when writing very large records to the WAL. #8790

  * TSDB: Avoid panic when mapped memory is referenced after the file is
           closed. #8723

  * Scaleway Discovery: Fix nil pointer dereference. #8737

  * Consul Discovery: Restart no longer required after config update
           with no targets. #8766
       + Features:

  * Promtool: Retroactive rule evaluation functionality.

  * Configuration: Environment variable expansion for external labels.
           Behind &#x27 --enable-feature=expand-external-labels&#x27  flag.

  * Add a flag &#x27 --storage.tsdb.max-block-chunk-segment-size&#x27  to control
           the max chunks file size of the blocks for small Prometheus
           instances.

  * UI: Add a dark theme.

  * AWS Lightsail Discovery: Add AWS Lightsail Discovery.

  * Docker Discovery: Add Docker Service Discovery.

  * OAuth: Allow OAuth 2.0 to be used anywhere an HTTP client is used.

  * Remote Write: Send exemplars via remote write. Experimental and
           disabled by default.
       + Enhancements:

  * Digital Ocean Discovery: Add &#x27 __meta_digitalocean_vpc&#x27  label.

  * Scaleway Discovery: Read Scaleway secret from a file.

  * Scrape: Add configurable limits for label size and count.

  * UI: Add 16w and 26w time range steps.

  * Templating: Enable parsing strings in humanize functions.

  - Update package with changes from `server:monitoring` (bsc#1175478) Left
       out removal of &#x27 firewalld&#x27  related configuration files as SUSE Linux
       Enterprise 15-SP1&#x27 s `firewalld` package does not contain &#x27 prometheus&#x27
       configuration yet.

     mgr-cfg:

  - No visible impact for the user

     mgr-custom-info:

  - No visible impact for the user

     mgr-osad:

  - No vi ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'SUSE' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.27.1~lp152.3.13.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.9.21~lp152.2.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-doc", rpm:"ansible-doc~2.9.21~lp152.2.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-test", rpm:"ansible-test~2.9.21~lp152.2.7.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~0.1.1627546504.96a0b3e~lp152.2.26.1", rls:"openSUSELeap15.2"))) {
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
