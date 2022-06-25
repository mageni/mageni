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
  script_oid("1.3.6.1.4.1.25623.1.0.854268");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2020-27304");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 02:03:33 +0000 (Mon, 01 Nov 2021)");
  script_name("openSUSE: Security Advisory for civetweb (openSUSE-SU-2021:1424-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1424-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YJTZUANR73SYTZDQ6GMWGRR5O4MCEJA4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'civetweb'
  package(s) announced via the openSUSE-SU-2021:1424-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for civetweb fixes the following issues:

     Version 1.15:

  * boo#1191938 / CVE-2020-27304: missing uploaded filepath validation in
       the default form-based file upload mechanism

  * New configuration for URL decoding

  * Sanitize filenames in handle form

  * Example embedded_c.c: Do not overwrite files (possible security
       issue)

  * Remove obsolete examples

  * Remove experimental label for some features

  * Remove MG_LEGACY_INTERFACE that have been declared obsolete in 2017 or
       earlier

  * Modifications to build scripts, required due to changes in the test
       environment

  * Unix domain socket support fixed

  * Fixes for NO_SSL_DL

  * Fixes for some warnings / static code analysis

     Version 1.14:

  * Change SSL default setting to use TLS 1.2 as minimum (set config if you
       need an earlier version)

  * Add local_uri_raw field (not sanitized URI) to request_info

  * Additional API functions and a callback after closing connections

  * Allow mbedTLS as OpenSSL alternative (basic functionality)

  * Add OpenSSL 3.0 support (OpenSSL 3.0 Alpha 13)

  * Support UNIX/Linux domain sockets

  * Fuzz tests and ossfuzz integration

  * Compression for websockets

  * Restructure some source files

  * Improve documentation

  * Fix HTTP range requests

  * Add some functions for Lua scripts/LSP

  * Build system specific fixes (CMake, MinGW)

  * Update 3rd party components (Lua, lfs, sqlite)

  * Allow Lua background script to use timers, format and filter logs

  * Remove WinCE code

  * Update version number

     Version 1.13:

  * Add arguments for CGI interpreters

  * Support multiple CGi interpreters

  * Buffering HTTP response headers, including API functions
       mg_response_header_* in C and Lua

  * Additional C API functions

  * Fix some memory leaks

  * Extended use of atomic operations (e.g., for server stats)

  * Add fuzz tests

  * Set OpenSSL 1.1 API as default (from 1.0)

  * Add Lua 5.4 support and deprecate Lua 5.1

  * Provide additional Lua API functions

  * Fix Lua websocket memory leak when closing the server

  * Remove obsolete 'file in memory' implementation

  * Improvements and fixes in documentation

  * Fixes from static source code analysis

  * Additional unit tests

  * Various small bug fixes

  * Experimental support for some HTTP2 features (not ready for production)

  * Experimental support for websocket compression

  * Remove legacy interfaces declared obs ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'civetweb' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"civetweb", rpm:"civetweb~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"civetweb-debuginfo", rpm:"civetweb-debuginfo~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"civetweb-debugsource", rpm:"civetweb-debugsource~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"civetweb-devel", rpm:"civetweb-devel~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcivetweb-cpp1_15_0", rpm:"libcivetweb-cpp1_15_0~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcivetweb-cpp1_15_0-debuginfo", rpm:"libcivetweb-cpp1_15_0-debuginfo~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcivetweb1_15_0", rpm:"libcivetweb1_15_0~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcivetweb1_15_0-debuginfo", rpm:"libcivetweb1_15_0-debuginfo~1.15~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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