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
  script_oid("1.3.6.1.4.1.25623.1.0.892984");
  script_version("2022-04-20T01:00:06+0000");
  script_cve_id("CVE-2022-26110");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-20 10:08:00 +0000 (Wed, 20 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-20 01:00:06 +0000 (Wed, 20 Apr 2022)");
  script_name("Debian LTS: Security Advisory for condor (DLA-2984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/04/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2984-1");
  script_xref(name:"Advisory-ID", value:"DLA-2984-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1008634");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'condor'
  package(s) announced via the DLA-2984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jaime Frey discovered a flaw in HTCondor, a distributed workload management
system. An attacker need only have READ-level authorization to a vulnerable
daemon using the CLAIMTOBE authentication method. This means they are able to
run tools like condor_q or condor_status. Many pools do not restrict who can
issue READ-level commands, and CLAIMTOBE is allowed for READ-level commands in
the default configuration. Thus, it is likely that an attacker could execute
this command remotely from an untrusted network, unless prevented by a firewall
or other network-level access controls.");

  script_tag(name:"affected", value:"'condor' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
8.4.11~dfsg.1-1+deb9u2.

We recommend that you upgrade your condor packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"condor", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"condor-dbg", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"condor-dev", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"condor-doc", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"htcondor", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"htcondor-dbg", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"htcondor-dev", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"htcondor-doc", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libclassad-dev", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libclassad7", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
