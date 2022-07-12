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
  script_oid("1.3.6.1.4.1.25623.1.0.854062");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-27962", "CVE-2021-28146", "CVE-2021-28147", "CVE-2021-28148", "CVE-2021-29622");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 03:01:28 +0000 (Fri, 13 Aug 2021)");
  script_name("openSUSE: Security Advisory for SUSE (openSUSE-SU-2021:2675-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2675-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/X43KWNU2XMSBJQO437DI7TR5WXTEXGK5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE'
  package(s) announced via the openSUSE-SU-2021:2675-1 advisory.");

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

  script_tag(name:"affected", value:"'SUSE' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"python2-uyuni-common-libs", rpm:"python2-uyuni-common-libs~4.2.5~1.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uyuni-common-libs", rpm:"python3-uyuni-common-libs~4.2.5~1.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.9.21~1.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-doc", rpm:"ansible-doc~2.9.21~1.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-test", rpm:"ansible-test~2.9.21~1.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~0.1.1627546504.96a0b3e~1.27.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg", rpm:"mgr-cfg~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-actions", rpm:"mgr-cfg-actions~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-client", rpm:"mgr-cfg-client~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-management", rpm:"mgr-cfg-management~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-custom-info", rpm:"mgr-custom-info~4.2.2~1.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osa-dispatcher", rpm:"mgr-osa-dispatcher~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-push", rpm:"mgr-push~4.2.3~1.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-virtualization-host", rpm:"mgr-virtualization-host~4.2.2~1.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg", rpm:"python2-mgr-cfg~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-actions", rpm:"python2-mgr-cfg-actions~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-client", rpm:"python2-mgr-cfg-client~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-management", rpm:"python2-mgr-cfg-management~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-dispatcher", rpm:"python2-mgr-osa-dispatcher~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-push", rpm:"python2-mgr-push~4.2.3~1.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-common", rpm:"python2-mgr-virtualization-common~4.2.2~1.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-host", rpm:"python2-mgr-virtualization-host~4.2.2~1.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.2.4~3.28.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-koan", rpm:"python2-spacewalk-koan~4.2.4~3.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-oscap", rpm:"python2-spacewalk-oscap~4.2.2~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-suseRegisterInfo", rpm:"python2-suseRegisterInfo~4.2.4~3.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-cfg", rpm:"python3-mgr-cfg~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-cfg-actions", rpm:"python3-mgr-cfg-actions~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-cfg-client", rpm:"python3-mgr-cfg-client~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-cfg-management", rpm:"python3-mgr-cfg-management~4.2.3~1.18.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-osa-common", rpm:"python3-mgr-osa-common~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-osa-dispatcher", rpm:"python3-mgr-osa-dispatcher~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-osad", rpm:"python3-mgr-osad~4.2.6~1.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-push", rpm:"python3-mgr-push~4.2.3~1.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-virtualization-common", rpm:"python3-mgr-virtualization-common~4.2.2~1.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mgr-virtualization-host", rpm:"python3-mgr-virtualization-host~4.2.2~1.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rhnlib", rpm:"python3-rhnlib~4.2.4~3.28.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-spacewalk-check", rpm:"python3-spacewalk-check~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-spacewalk-client-setup", rpm:"python3-spacewalk-client-setup~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-spacewalk-client-tools", rpm:"python3-spacewalk-client-tools~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-spacewalk-koan", rpm:"python3-spacewalk-koan~4.2.4~3.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-spacewalk-oscap", rpm:"python3-spacewalk-oscap~4.2.2~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-suseRegisterInfo", rpm:"python3-suseRegisterInfo~4.2.4~3.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.2.11~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.2.12~3.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-koan", rpm:"spacewalk-koan~4.2.4~3.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-oscap", rpm:"spacewalk-oscap~4.2.2~3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"suseRegisterInfo", rpm:"suseRegisterInfo~4.2.4~3.15.1", rls:"openSUSELeap15.3"))) {
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
