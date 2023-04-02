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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0733.1");
  script_cve_id("CVE-2022-41722", "CVE-2022-41723", "CVE-2022-41724", "CVE-2022-41725", "CVE-2023-24532");
  script_tag(name:"creation_date", value:"2023-03-28 13:04:06 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-29T10:10:12+0000");
  script_tag(name:"last_modification", value:"2023-03-29 10:10:12 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-10 04:58:00 +0000 (Fri, 10 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0733-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0733-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230733-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.19' package(s) announced via the SUSE-SU-2023:0733-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.19 fixes the following issues:

CVE-2022-41722: Fixed path traversal in filepath.Clean on Windows (bsc#1208269).
CVE-2022-41723: Fixed quadratic complexity in HPACK decoding (bsc#1208270).
CVE-2022-41724: Fixed panic with arge handshake records in crypto/tls (bsc#1208271).
CVE-2022-41725: Fixed denial of service from excessive resource consumption in net/http and mime/multipart (bsc#1208272).
CVE-2023-24532: Fixed incorrect P-256 ScalarMult and ScalarBaseMult results (bsc#1209030).

Update to go1.19.7
* go#58441 runtime: some linkname signatures do not match
* go#58502 cmd/link: relocation truncated to fit: R_ARM_CALL against `runtime.duffcopy'
* go#58535 runtime: long latency of sweep assists
* go#58716 net: TestTCPSelfConnect failures due to unexpected connections
* go#58773 syscall: Environ uses an invalid unsafe.Pointer conversion on Windows
* go#58810 crypto/x509: TestSystemVerify consistently failing Update to go1.19.6:
* go#56154 net/http: bad handling of HEAD requests with a body
* go#57635 crypto/x509: TestBoringAllowCert failures
* go#57812 runtime: performance regression due to bad instruction used in morestack_noctxt for ppc64 in CL 425396
* go#58118 time: update zoneinfo_abbrs on Windows
* go#58223 cmd/link: .go.buildinfo is gc'ed by --gc-sections
* go#58449 cmd/go/internal/modfetch: TestCodeRepo/gopkg.in_natefinch_lumberjack.v2/latest failing Update to go1.19.5 (bsc#1200441):
* go#57706 Misc/cgo: backport needed for dlltool fix
* go#57556 crypto/x509: re-allow duplicate attributes in CSRs
* go#57444 cmd/link: need to handle new-style LoongArch relocs
* go#57427 crypto/x509: Verify on macOS does not return typed errors
* go#57345 cmd/compile: the loong64 intrinsic for CompareAndSwapUint32 function needs to sign extend its 'old' argument.
* go#57339 syscall, internal/poll: accept4-to-accept fallback removal broke Go code on Synology DSM 6.2 ARM devices
* go#57214 os: TestLstat failure on Linux Aarch64
* go#57212 reflect: sort.SliceStable sorts incorrectly on arm64 with less function created with reflect.MakeFunc and slice of sufficient length
* go#57124 sync/atomic: allow linked lists of atomic.Pointer
* go#57100 cmd/compile: non-retpoline-compatible errors
* go#57058 cmd/go: remove test dependency on gopkg.in service
* go#57055 cmd/go: TestScript/version_buildvcs_git_gpg (if enabled) fails on linux longtest builders
* go#56983 runtime: failure in TestRaiseException on windows-amd64-2012
* go#56834 cmd/link/internal/ppc64: too-far trampoline is reused
* go#56770 cmd/compile: walkConvInterface produces broken IR
* go#56744 cmd/compile: internal compiler error: missing typecheck
* go#56712 net: re-enable TestLookupDotsWithRemoteSource and TestLookupGoogleSRV with a different target
* go#56154 net/http: bad handling of HEAD requests with a body");

  script_tag(name:"affected", value:"'go1.19' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.19", rpm:"go1.19~1.19.7~150000.1.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.19-doc", rpm:"go1.19-doc~1.19.7~150000.1.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.19-race", rpm:"go1.19-race~1.19.7~150000.1.23.1", rls:"SLES15.0SP3"))) {
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
