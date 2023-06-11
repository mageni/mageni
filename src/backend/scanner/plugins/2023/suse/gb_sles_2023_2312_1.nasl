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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2312.1");
  script_cve_id("CVE-2022-1705", "CVE-2022-1962", "CVE-2022-24675", "CVE-2022-27536", "CVE-2022-27664", "CVE-2022-28131", "CVE-2022-28327", "CVE-2022-2879", "CVE-2022-2880", "CVE-2022-29526", "CVE-2022-29804", "CVE-2022-30580", "CVE-2022-30629", "CVE-2022-30630", "CVE-2022-30631", "CVE-2022-30632", "CVE-2022-30633", "CVE-2022-30634", "CVE-2022-30635", "CVE-2022-32148", "CVE-2022-32189", "CVE-2022-41715", "CVE-2022-41716", "CVE-2022-41717", "CVE-2022-41720", "CVE-2022-41723", "CVE-2022-41724", "CVE-2022-41725");
  script_tag(name:"creation_date", value:"2023-05-31 04:21:14 +0000 (Wed, 31 May 2023)");
  script_version("2023-05-31T09:08:55+0000");
  script_tag(name:"last_modification", value:"2023-05-31 09:08:55 +0000 (Wed, 31 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-12 20:46:00 +0000 (Fri, 12 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2312-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2312-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232312-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.18-openssl' package(s) announced via the SUSE-SU-2023:2312-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.18-openssl fixes the following issues:

Add subpackage go1.x-libstd compiled shared object libstd.so (jsc#PED-1962)
Main go1.x package included libstd.so in previous versions Split libstd.so into subpackage that can be installed standalone Continues the slimming down of main go1.x package by 40 Mb Experimental and not recommended for general use, Go currently has no ABI Upstream Go has not committed to support buildmode=shared long-term Do not use in packaging, build static single binaries (the default)
Upstream Go go1.x binary releases do not include libstd.so go1.x Suggests go1.x-libstd so not installed by default Recommends go1.x-libstd does not Require: go1.x so can install standalone Provides go-libstd unversioned package name Fix build step -buildmode=shared std to omit -linkshared Packaging improvements:
go1.x Suggests go1.x-doc so not installed by default Recommends

Use Group: Development/Languages/Go instead of Other


Improvements to go1.x packaging spec:

On Tumbleweed bootstrap with current default gcc13 and gccgo118 On SLE-12 aarch64 ppc64le ppc64 remove overrides to bootstrap
 using go1.x package (%bcond_without gccgo). This is no longer
 needed on current SLE-12:Update and removing will consolidate
 the build configurations used.
Change source URLs to go.dev as per Go upstream On x86_64 export GOAMD64=v1 as per the current baseline.
 At this time forgo GOAMD64=v3 option for x86_64_v3 support.

On x86_64 %define go_amd64=v1 as current instruction baseline


Update to version 1.18.10.1 cut from the go1.18-openssl-fips
 branch at the revision tagged go1.18.10-1-openssl-fips.

Merge branch dev.boringcrypto.go1.18 into go1.18-openssl-fips

Merge go1.18.10 into dev.boringcrypto.go1.18


go1.18.10 (released 2023-01-10) includes fixes to cgo, the
 compiler, the linker, and the crypto/x509, net/http, and syscall
 packages.
 Refs bsc#1193742 go1.18 release tracking

go#57705 misc/cgo: backport needed for dlltool fix go#57426 crypto/x509: Verify on macOS does not return typed errors go#57344 cmd/compile: the loong64 intrinsic for CompareAndSwapUint32 function needs to sign extend its 'old' argument.
go#57338 syscall, internal/poll: accept4-to-accept fallback removal broke Go code on Synology DSM 6.2 ARM devices go#57213 os: TestLstat failure on Linux Aarch64 go#57211 reflect: sort.SliceStable sorts incorrectly on arm64 with less function created with reflect.MakeFunc and slice of sufficient length go#57057 cmd/go: remove test dependency on gopkg.in service go#57054 cmd/go: TestScript/version_buildvcs_git_gpg (if enabled) fails on linux longtest builders go#57044 cgo: malformed DWARF TagVariable entry go#57028 cmd/cgo: Wrong types in compiler errors with clang 14 go#56833 cmd/link/internal/ppc64: too-far trampoline is reused go#56711 net: re-enable TestLookupDotsWithRemoteSource and TestLookupGoogleSRV with a different target go#56323 net/http: bad handling of HEAD requests with a body");

  script_tag(name:"affected", value:"'go1.18-openssl' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.18-openssl", rpm:"go1.18-openssl~1.18.10.1~150000.1.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.18-openssl-doc", rpm:"go1.18-openssl-doc~1.18.10.1~150000.1.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.18-openssl-race", rpm:"go1.18-openssl-race~1.18.10.1~150000.1.9.1", rls:"SLES15.0SP3"))) {
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
