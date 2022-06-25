# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853264");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2018-1000667", "CVE-2018-10016", "CVE-2018-10254", "CVE-2018-10316", "CVE-2018-16382", "CVE-2018-16517", "CVE-2018-16999", "CVE-2018-19214", "CVE-2018-19215", "CVE-2018-19216", "CVE-2018-8881", "CVE-2018-8882", "CVE-2018-8883");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-14 03:01:25 +0000 (Tue, 14 Jul 2020)");
  script_name("openSUSE: Security Advisory for nasm (openSUSE-SU-2020:0952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0952-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nasm'
  package(s) announced via the openSUSE-SU-2020:0952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nasm fixes the following issues:

  nasm was updated to version 2.14.02.

  This allows building of Mozilla Firefox 78ESR and also contains lots of
  bugfixes, security fixes and improvements.

  * Fix crash due to multiple errors or warnings during the code generation
  pass if a list file is specified.

  * Create all system-defined macros before processing command-line given
  preprocessing directives (-p, -d, -u, --pragma, --before).

  * If debugging is enabled, define a __DEBUG_FORMAT__ predefined macro. See
  section 4.11.7.

  * Fix an assert for the case in the obj format when a SEG operator refers
  to an EXTERN symbol declared further down in the code.

  * Fix a corner case in the floating-point code where a binary, octal or
  hexadecimal floating-point having at least 32, 11, or 8 mantissa digits
  could produce slightly incorrect results under very specific conditions.

  * Support -MD without a filename, for gcc compatibility. -MF can be used
  to set the dependencies output filename. See section 2.1.7.

  * Fix -E in combination with -MD. See section 2.1.21.

  * Fix missing errors on redefined labels, would cause convergence failure
  instead which is very slow and not easy to debug.

  * Duplicate definitions of the same label with the same value is now
  explicitly permitted (2.14 would allow it in some circumstances.)

  * Add the option --no-line to ignore %line directives in the source. See
  section 2.1.33 and section 4.10.1.

  * Changed -I option semantics by adding a trailing path separator
  unconditionally.

  * Fixed null dereference in corrupted invalid single line macros.

  * Fixed division by zero which may happen if source code is malformed.

  * Fixed out of bound access in processing of malformed segment override.

  * Fixed out of bound access in certain EQU parsing.

  * Fixed buffer underflow in float parsing.

  * Added SGX (Intel Software Guard Extensions) instructions.

  * Added +n syntax for multiple contiguous registers.

  * Fixed subsections_via_symbols for macho object format.

  * Added the --gprefix, --gpostfix, --lprefix, and --lpostfix command line
  options, to allow command line base symbol renaming. See section 2.1.28.

  * Allow label renaming to be specified by %pragma in addition to from the
  command line. See section 6.9.

  * Supported generic %pragma namespaces, output and debug. See section 6.10.

  * Added the --pragma command line option to inject a %pragma directive.
  See section 2.1.29.

  * Added the --before command line option to accept preprocess statement
  before input. See section 2.1.30.

  * Added AVX512 VBMI2 (Additional ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'nasm' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"nasm", rpm:"nasm~2.14.02~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-debuginfo", rpm:"nasm-debuginfo~2.14.02~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-debugsource", rpm:"nasm-debugsource~2.14.02~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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
