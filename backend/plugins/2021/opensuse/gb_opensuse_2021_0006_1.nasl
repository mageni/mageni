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
  script_oid("1.3.6.1.4.1.25623.1.0.853647");
  script_version("2021-04-21T07:29:02+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:58:38 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for privoxy (openSUSE-SU-2021:0006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0006-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JFSIXZ2RYSIQJKMIUICOI4Y4Q5L52U6T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'privoxy'
  package(s) announced via the openSUSE-SU-2021:0006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for privoxy fixes the following issues:

     privoxy was updated to 3.0.29:

  * Fixed memory leaks when a response is buffered and the buffer limit is
       reached or Privoxy is running out of memory. OVE-20201118-0001

  * Fixed a memory leak in the show-status CGI handler when no action files
       are configured OVE-20201118-0002

  * Fixed a memory leak in the show-status CGI handler when no filter files
       are configured OVE-20201118-0003

  * Fixes a memory leak when client tags are active OVE-20201118-0004

  * Fixed a memory leak if multiple filters are executed and the last one is
       skipped due to a pcre error OVE-20201118-0005

  * Prevent an unlikely dereference of a NULL-pointer that could result in a
       crash if accept-intercepted-requests was enabled, Privoxy failed to get
       the request destination from the Host header and a memory allocation
       failed. OVE-20201118-0006

  * Fixed memory leaks in the client-tags CGI handler when client tags are
       configured and memory allocations fail. OVE-20201118-0007

  * Fixed memory leaks in the show-status CGI handler when memory
       allocations fail OVE-20201118-0008

  * Add experimental https inspection support

  * Use JIT compilation for static filtering for speedup

  * Add support for Brotli decompression, add &#x27 no-brotli-accepted&#x27  filter
       which prevents the use of Brotli compression

  * Add feature to gather extended statistics

  * Use IP_FREEBIND socket option to help with failover

  * Allow to use extended host patterns and vanilla host patterns at the
       same time by prefixing extended host patterns with 'PCRE-HOST-PATTERN:'

  * Added 'Cross-origin resource sharing' (CORS) support

  * Add SOCKS5 username/password support

  * Bump the maximum number of action and filter files to 100 each

  * Fixed handling of filters with 'split-large-forms 1' when using the CGI
       editor.

  * Better detect a mismatch of connection details when figuring out whether
       or not a connection can be reused

  * Don&#x27 t send a 'Connection failure' message instead of the 'DNS
  failure'
       message

  * Let LOG_LEVEL_REQUEST log all requests

  * Improvements to default Action file

     License changed to GPLv3.

  - remove packaging vulnerability boo#1157449");

  script_tag(name:"affected", value:"'privoxy' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"privoxy-doc", rpm:"privoxy-doc~3.0.29~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy", rpm:"privoxy~3.0.29~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debuginfo", rpm:"privoxy-debuginfo~3.0.29~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debugsource", rpm:"privoxy-debugsource~3.0.29~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"privoxy-doc", rpm:"privoxy-doc~3.0.29~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy", rpm:"privoxy~3.0.29~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debuginfo", rpm:"privoxy-debuginfo~3.0.29~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debugsource", rpm:"privoxy-debugsource~3.0.29~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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
