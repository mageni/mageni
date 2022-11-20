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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.320.03");
  script_cve_id("CVE-2022-45403", "CVE-2022-45404", "CVE-2022-45405", "CVE-2022-45406", "CVE-2022-45408", "CVE-2022-45409", "CVE-2022-45410", "CVE-2022-45411", "CVE-2022-45412", "CVE-2022-45416", "CVE-2022-45418", "CVE-2022-45420", "CVE-2022-45421");
  script_tag(name:"creation_date", value:"2022-11-17 04:22:43 +0000 (Thu, 17 Nov 2022)");
  script_version("2022-11-17T04:22:43+0000");
  script_tag(name:"last_modification", value:"2022-11-17 04:22:43 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2022-320-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2022-320-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.411598");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45403");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45404");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45405");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45406");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45408");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45409");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45410");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45411");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45412");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45416");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45418");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45420");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45421");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-49/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird/102.5.0/releasenotes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird' package(s) announced via the SSA:2022-320-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-thunderbird packages are available for Slackware 15.0 and -current
to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-thunderbird-102.5.0-i686-1_slack15.0.txz: Upgraded.
 This release contains security fixes and improvements.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"102.5.0-i686-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"102.5.0-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"102.5.0-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"102.5.0-x86_64-1", rls:"SLKcurrent"))) {
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
