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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2007.165.01");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-04-26T09:43:38+0000");
  script_tag(name:"last_modification", value:"2022-04-26 09:43:38 +0000 (Tue, 26 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2007-165-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLKcurrent");

  script_xref(name:"Advisory-ID", value:"SSA:2007-165-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.339692");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#thunderbird");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the SSA:2007-165-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A new thunderbird package is available for Slackware -current to
fix two possible security issues. This package may also be used on
many older versions of Slackware (though we're not certain how far
back...)

More details about the issues may be found here:
 [link moved to references]


Here are the details from the Slackware -current ChangeLog:
+--------------------------+
xap/mozilla-thunderbird-2.0.0.4-i686-1.tgz: Upgraded to thunderbird-2.0.0.4.
 This upgrade fixes two possible security bugs.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.4-i686-1", rls:"SLKcurrent"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
