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
  script_oid("1.3.6.1.4.1.25623.1.0.822542");
  script_version("2022-09-28T10:12:17+0000");
  script_cve_id("CVE-2022-2200", "CVE-2022-2505", "CVE-2022-34468", "CVE-2022-34469", "CVE-2022-34470", "CVE-2022-34471", "CVE-2022-34472", "CVE-2022-34473", "CVE-2022-34474", "CVE-2022-34475", "CVE-2022-34476", "CVE-2022-34477", "CVE-2022-34478", "CVE-2022-34479", "CVE-2022-34480", "CVE-2022-34481", "CVE-2022-34482", "CVE-2022-34483", "CVE-2022-34484", "CVE-2022-34485", "CVE-2022-36314", "CVE-2022-36318", "CVE-2022-36319", "CVE-2022-38472", "CVE-2022-38473", "CVE-2022-38476", "CVE-2022-38477", "CVE-2022-38478", "CVE-2022-40956", "CVE-2022-40957", "CVE-2022-40958", "CVE-2022-40959", "CVE-2022-40960", "CVE-2022-40962");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-28 10:12:17 +0000 (Wed, 28 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-27 01:03:26 +0000 (Tue, 27 Sep 2022)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2022:3396-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3396-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZBJC27LL56JNBZLNU6PSXKASJMCNST6G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2022:3396-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:
  Mozilla Firefox was updated to 102.3.0esr ESR (bsc#1200793, bsc#1201758,
     bsc#1202645, bsc#1203477):

  - CVE-2022-40959: Fixed bypassing FeaturePolicy restrictions on transient
       pages.

  - CVE-2022-40960: Fixed data-race when parsing non-UTF-8 URLs in threads.

  - CVE-2022-40958: Fixed bypassing secure context restriction for cookies
       with __Host and __Secure prefix.

  - CVE-2022-40956: Fixed content-security-policy base-uri bypass.

  - CVE-2022-40957: Fixed incoherent instruction cache when building WASM on
       ARM64.

  - CVE-2022-40962: Fixed memory safety bugs.

  - CVE-2022-38472: Fixed a potential address bar spoofing via XSLT error
       handling.

  - CVE-2022-38473: Fixed an issue where cross-origin XSLT documents could
       inherit the parent's permissions.

  - CVE-2022-38478: Fixed various memory safety issues.

  - CVE-2022-38476: Fixed data race and potential use-after-free in
       PK11_ChangePW.

  - CVE-2022-38477: Fixed memory safety bugs.

  - CVE-2022-36319: Fixed mouse position spoofing with CSS transforms.

  - CVE-2022-36318: Fixed directory indexes for bundled resources reflected
       URL parameters.

  - CVE-2022-36314: Fixed unexpected network loads when opening local .lnk
       files.

  - CVE-2022-2505: Fixed memory safety bugs.

  - CVE-2022-34479: Fixed vulnerability where a popup window could be resized
       in a way to overlay the address bar with web content.

  - CVE-2022-34470: Fixed use-after-free in nsSHistory.

  - CVE-2022-34468: Fixed bypass of CSP sandbox header without
       `allow-scripts` via retargeted javascript: URI.

  - CVE-2022-34482: Fixed drag and drop of malicious image that could have
       led to malicious executable and potential code execution.

  - CVE-2022-34483: Fixed drag and drop of malicious image that could have
       led to malicious executable and potential code execution.

  - CVE-2022-34476: Fixed vulnerability where ASN.1 parser could have been
       tricked into accepting malformed ASN.1.

  - CVE-2022-34481: Fixed potential integer overflow in ReplaceElementsAt

  - CVE-2022-34474: Fixed vulnerability where sandboxed iframes could
       redirect to external schemes.

  - CVE-2022-34469: Fixed TLS certificate errors on HSTS-protected domains
       which could be bypassed by the user on Firefox for Android.

  - CVE-2022-34471: Fixed vulnerability where a compromised server could
       trick a browser into an addon downgrade.

  - CVE-2022- ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~102.3.0~150200.152.61.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE-102", rpm:"MozillaFirefox-branding-SLE-102~150200.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~102.3.0~150200.152.61.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~102.3.0~150200.152.61.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~102.3.0~150200.152.61.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~102.3.0~150200.152.61.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~102.3.0~150200.152.61.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~102.3.0~150200.152.61.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~102.3.0~150200.152.61.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE-102", rpm:"MozillaFirefox-branding-SLE-102~150200.9.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~102.3.0~150200.152.61.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~102.3.0~150200.152.61.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~102.3.0~150200.152.61.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~102.3.0~150200.152.61.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~102.3.0~150200.152.61.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~102.3.0~150200.152.61.1", rls:"openSUSELeap15.3"))) {
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
