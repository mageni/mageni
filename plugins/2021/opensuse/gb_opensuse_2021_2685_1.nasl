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
  script_oid("1.3.6.1.4.1.25623.1.0.854066");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-20271", "CVE-2021-3421", "CVE-2021-3445");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-14 03:01:31 +0000 (Sat, 14 Aug 2021)");
  script_name("openSUSE: Security Advisory for libdnf (openSUSE-SU-2021:2685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2685-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PUJW4L55UGKEL4ROYV7WZNQDNBJXXLLG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libdnf'
  package(s) announced via the openSUSE-SU-2021:2685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libdnf fixes the following issues:

  - Fixed crash when loading DVD repositories

     Update to 0.62.0

     + Change order of TransactionItemReason (rh#1921063)
     + Add two new comperators for security filters (rh#1918475)
     + Apply security filters for candidates with lower priority
     + Fix: Goal - translation of messages in global maps
     + Enhance description of modular solvables
     + Improve performance for module query
     + Change mechanism of modular errata applicability (rh#1804234)
     + dnf_transaction_commit(): Remove second call to rpmtsSetVSFlags
     + Fix a couple of memory leaks
     + Fix: Setting of librepo handle in newHandle function
     + Remove failsafe data when module is not enabled (rh#1847035)
     + Expose librepo&#x27 s checksum functions via SWIG
     + Fix:  Missing check of 'hy_split_nevra()' return code
     + Do not allow 1 as installonly_limit value (rh#1926261)
     + Fix check whether the subkey can be used for signing
     + Hardening: add signature check with rpmcliVerifySignatures
       (CVE-2021-3445, CVE-2021-3421, CVE-2021-20271, rh#1932079, rh#1932089,
       rh#1932090, bsc#1183779)
     + Add a config option sslverifystatus, defaults to false (rh#1814383)
     + [context] Add API for distro-sync

  - Fix dependency for repo-config-zypp subpackage to work with SLE

     Update to 0.60.0

     + Fix repo.fresh() implementation
     + Fix: Fully set ssl in newHandle function
     + [conf] Add options for working with certificates used with proxy
     + Apply proxy certificate options
     + lock: Switch return-if-fail to assert to quiet gcc -fanalyzer
     + build-sys: Clean up message about Python bindings
     + Modify module NSVCA parsing - context definition (rh#1926771)
     + [context] Fix: dnf_package_is_installonly (rh#1928056)
     + Fix problematic language
     + Add getApplicablePackages to advisory and isApplicable to advisorymodule
     + Keep isAdvisoryApplicable to preserve API
     + Run ModulePackageContainerTest tests in tmpdir, merge interdependent
     + [context] Support config file option 'proxy_auth_method', defaults
  'any'
     + Properly handle multiple collections in updateinfo.xml (rh#1804234)
     + Support main config file option 'installonlypkgs'
     + Support main config file option 'protected_packages'

  - Add repo-config-zypp subpackage to allow easily using Zypper repository
       configuration

  - Backport support for using certificates for repository authorization

  - Backport another fix for adding controls to installonlypkgs

  - Add patch to move di ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'libdnf' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libdnf-debuginfo", rpm:"libdnf-debuginfo~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf-debugsource", rpm:"libdnf-debugsource~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf-devel", rpm:"libdnf-devel~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf-repo-config-zypp", rpm:"libdnf-repo-config-zypp~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf2", rpm:"libdnf2~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf2-debuginfo", rpm:"libdnf2-debuginfo~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hawkey", rpm:"python3-hawkey~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hawkey-debuginfo", rpm:"python3-hawkey-debuginfo~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf", rpm:"python3-libdnf~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf-debuginfo", rpm:"python3-libdnf-debuginfo~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawkey-man", rpm:"hawkey-man~0.62.0~5.3.1", rls:"openSUSELeap15.3"))) {
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
