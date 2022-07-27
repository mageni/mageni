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
  script_oid("1.3.6.1.4.1.25623.1.0.891723");
  script_version("2019-03-25T09:51:34+0000");
  script_cve_id("CVE-2017-9525", "CVE-2019-9704", "CVE-2019-9705", "CVE-2019-9706");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1723-1] cron security update)");
  script_tag(name:"last_modification", value:"2019-03-25 09:51:34 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-21 23:00:00 +0100 (Thu, 21 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00025.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/06/08/3");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"cron on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.0pl1-127+deb8u2.

We recommend that you upgrade your cron packages.");
  script_tag(name:"summary", value:"Various security problems have been discovered in Debian's CRON scheduler.

CVE-2017-9525

    Fix group crontab to root escalation via the Debian package's
    postinst script as described by Alexander Peslyak (Solar Designer) in
    the linked references.

CVE-2019-9704

    DoS: Fix unchecked return of calloc(). Florian Weimer discovered that
    a missing check for the return value of calloc() could crash the
    daemon, which could be triggered by a very large crontab created by a
    user.

CVE-2019-9705

    Enforce maximum crontab line count of 1000 to prevent a malicious
    user from creating an excessivly large crontab. The daemon will log a
    warning for existing files, and crontab(1) will refuse to create new
    ones.

CVE-2019-9706

    A user reported a use-after-free condition in the cron daemon,
    leading to a possible Denial-of-Service scenario by crashing the
    daemon.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cron", ver:"3.0pl1-127+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
