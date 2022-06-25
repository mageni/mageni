# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852621");
  script_version("2019-07-25T11:54:35+0000");
  script_cve_id("CVE-2017-12481", "CVE-2017-12482", "CVE-2017-2807", "CVE-2017-2808");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-22 02:00:39 +0000 (Mon, 22 Jul 2019)");
  script_name("openSUSE Update for ledger openSUSE-SU-2019:1779-1 (ledger)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ledger'
  package(s) announced via the openSUSE-SU-2019:1779_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ledger fixes the following issues:

  ledger was updated to 3.1.3:

  + Properly reject postings with a comment right after the flag (bug #1753)
  + Make sorting order of lot information deterministic (bug #1747)
  + Fix bug in tag value parsing (bug #1702)
  + Remove the org command, which was always a hack to begin with (bug #1706)
  + Provide Docker information in README
  + Various small documentation improvements

  This also includes the update to 3.1.2:

  + Increase maximum length for regex from 255 to 4095 (bug #981)
  + Initialize periods from from/since clause rather than earliest
  transaction date (bug #1159)
  + Check balance assertions against the amount after the posting (bug #1147)
  + Allow balance assertions with multiple posts to same account (bug #1187)
  + Fix period duration of 'every X days' and similar statements (bug #370)
  + Make option --force-color not require --color anymore (bug #1109)
  + Add quoted_rfc4180 to allow CVS output with RFC 4180 compliant quoting.
  + Add support for --prepend-format in accounts command
  + Fix handling of edge cases in trim function (bug #520)
  + Fix auto xact posts not getting applied to account total during journal
  parse (bug #552)
  + Transfer null_post flags to generated postings
  + Fix segfault when using --market with --group-by
  + Use amount_width variable for budget report
  + Keep pending items in budgets until the last day they apply
  + Fix bug where .total used in value expressions breaks totals
  + Make automated transactions work with assertions (bug #1127)
  + Improve parsing of date tokens (bug #1626)
  + Don't attempt to invert a value if it's already zero (bug #1703)
  + Do not parse user-specified init-file twice
  + Fix parsing issue of effective dates (bug #1722, TALOS-2017-0303,
  CVE-2017-2807)
  + Fix use-after-free issue with deferred postings (bug #1723,
  TALOS-2017-0304, CVE-2017-2808)
  + Fix possible stack overflow in option parsing routine (bug #1222,
  CVE-2017-12481)
  + Fix possible stack overflow in date parsing routine (bug #1224,
  CVE-2017-12482)
  + Fix use-after-free when using --gain (bug #541)
  + Python: Removed double quotes from Unicode values.
  + Python: Ensure that parse errors produce useful RuntimeErrors
  + Python: Expose journal expand_aliases
  + Python: Expose journal_t::register_account
  + Improve bash completion
  + Various documentation improvements


  Patch Instructions:

  To install this openSUSE Security ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ledger' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ledger", rpm:"ledger~3.1.3~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ledger-debuginfo", rpm:"ledger-debuginfo~3.1.3~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ledger-debugsource", rpm:"ledger-debugsource~3.1.3~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
