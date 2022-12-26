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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.341.01");
  script_cve_id("CVE-2015-20107", "CVE-2022-37454", "CVE-2022-42919", "CVE-2022-43680", "CVE-2022-45061");
  script_tag(name:"creation_date", value:"2022-12-08 04:17:58 +0000 (Thu, 08 Dec 2022)");
  script_version("2022-12-08T10:12:32+0000");
  script_tag(name:"last_modification", value:"2022-12-08 10:12:32 +0000 (Thu, 08 Dec 2022)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:00 +0000 (Wed, 09 Nov 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-341-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2022-341-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.508110");
  script_xref(name:"URL", value:"https://pythoninsider.blogspot.com/2022/12/python-3111-3109-3916-3816-3716-and.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2015-20107");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-37454");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-42919");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-43680");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45061");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the SSA:2022-341-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New python3 packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/python3-3.9.16-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 gh-98739: Updated bundled libexpat to 2.5.0 to fix CVE-2022-43680
 (heap use-after-free).
 gh-98433: The IDNA codec decoder used on DNS hostnames by socket or asyncio
 related name resolution functions no longer involves a quadratic algorithm
 to fix CVE-2022-45061. This prevents a potential CPU denial of service if an
 out-of-spec excessive length hostname involving bidirectional characters were
 decoded. Some protocols such as urllib http 3xx redirects potentially allow
 for an attacker to supply such a name.
 gh-100001: python -m http.server no longer allows terminal control characters
 sent within a garbage request to be printed to the stderr server log.
 gh-87604: Avoid publishing list of active per-interpreter audit hooks via the
 gc module.
 gh-97514: On Linux the multiprocessing module returns to using filesystem
 backed unix domain sockets for communication with the forkserver process
 instead of the Linux abstract socket namespace. Only code that chooses to use
 the 'forkserver' start method is affected. This prevents Linux CVE-2022-42919
 (potential privilege escalation) as abstract sockets have no permissions and
 could allow any user on the system in the same network namespace (often the
 whole system) to inject code into the multiprocessing forkserver process.
 Filesystem based socket permissions restrict this to the forkserver process
 user as was the default in Python 3.8 and earlier.
 gh-98517: Port XKCP's fix for the buffer overflows in SHA-3 to fix
 CVE-2022-37454.
 gh-68966: The deprecated mailcap module now refuses to inject unsafe text
 (filenames, MIME types, parameters) into shell commands to address
 CVE-2015-20107. Instead of using such text, it will warn and act as if a
 match was not found (or for test commands, as if the test failed).
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'python3' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.16-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.16-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.16-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.16-x86_64-1", rls:"SLKcurrent"))) {
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
