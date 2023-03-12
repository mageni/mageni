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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0419.1");
  script_cve_id("CVE-2022-32212", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215", "CVE-2022-35255", "CVE-2022-35256", "CVE-2022-43548");
  script_tag(name:"creation_date", value:"2023-02-16 04:21:52 +0000 (Thu, 16 Feb 2023)");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-08 15:58:00 +0000 (Thu, 08 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0419-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0419-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230419-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs18' package(s) announced via the SUSE-SU-2023:0419-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs18 fixes the following issues:

This update ships nodejs18 (jsc#PED-2097)

Update to NodejJS 18.13.0 LTS:

build: disable v8 snapshot compression by default

crypto: update root certificates

deps: update ICU to 72.1

doc:

 + add doc-only deprecation for headers/trailers setters
 + add Rafael to the tsc
 + deprecate use of invalid ports in url.parse
 + deprecate url.parse()

lib: drop fetch experimental warning

net: add autoSelectFamily and autoSelectFamilyAttemptTimeout options

src:

 + add uvwasi version
 + add initial shadow realm support

test_runner:

 + add t.after() hook
 + don't use a symbol for runHook()

tls:

 + add 'ca' property to certificate object

util:

 + add fast path for utf8 encoding
 + improve textdecoder decode performance
 + add MIME utilities

Fixes compatibility with ICU 72.1 (bsc#1205236)

Fix migration to openssl-3 (bsc#1205042)

Update to NodeJS 18.12.1 LTS:

inspector: DNS rebinding in --inspect via invalid octal IP (bsc#1205119,
 CVE-2022-43548)

Update to NodeJS 18.12.0 LTS:

Running in 'watch' mode using node --watch restarts the process when an
 imported file is changed.

fs: add FileHandle.prototype.readLines

http: add writeEarlyHints function to ServerResponse

http2: make early hints generic

util: add default value option to parsearg

Update to NodeJS 18.11.0:

added experimental watch mode -- running in 'watch' mode using node
 --watch restarts the process when an imported file is changed

fs: add FileHandle.prototype.readLines

http: add writeEarlyHints function to ServerResponse

http2: make early hints generic

lib: refactor transferable AbortSignal

src: add detailed embedder process initialization API

util: add default value option to parsearg

Update to NodeJS 18.10.0:

deps: upgrade npm to 8.19.2

http: throw error on content-length mismatch

stream: add ReadableByteStream.tee()

Update to Nodejs 18.9.1:

deps: llhttp updated to 6.0.10

 + CVE-2022-32213 bypass via obs-fold mechanic (bsc#1201325)
 + Incorrect Parsing of Multi-line Transfer-Encoding (CVE-2022-32215,
 bsc#1201327)
 + Incorrect Parsing of Header Fields (CVE-2022-35256, bsc#1203832)

crypto: fix weak randomness in WebCrypto keygen (CVE-2022-35255,
 bsc#1203831)

Update to Nodejs 18.9.0:

lib - add diagnostics channel for process and worker

os - add machine method

report - expose report public native apis

src - expose environment RequestInterrupt api

vm - include vm context in the embedded snapshot

Changes in 18.8.0:

bootstrap: implement run-time user-land snapshots via
 --build-snapshot and --snapshot-blob. See

crypto:
 + allow zero-length IKM in HKDF and in webcrypto PBKDF2
 + allow zero-length secret KeyObject

deps: upgrade npm to 8.18.0

http: make idle http parser count configurable

net: add local family

src: print source map error source on demand

tls: pass a valid socket on tlsClientError

Update to Nodejs ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'nodejs18' package(s) on SUSE Linux Enterprise Module for Web Scripting 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.13.0~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debuginfo", rpm:"nodejs18-debuginfo~18.13.0~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debugsource", rpm:"nodejs18-debugsource~18.13.0~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.13.0~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.13.0~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.13.0~150400.9.3.1", rls:"SLES15.0SP4"))) {
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
