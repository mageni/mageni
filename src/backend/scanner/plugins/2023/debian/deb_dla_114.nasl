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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.114");
  script_cve_id("CVE-2004-2771", "CVE-2014-7844");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 16:05:00 +0000 (Tue, 21 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-114)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-114");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-114");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heirloom-mailx' package(s) announced via the DLA-114 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security vulnerabilities were discovered in Heirloom mailx, an implementation of the mail command:

CVE-2004-2771

mailx interprets shell meta-characters in certain email addresses.

CVE-2014-7844

An unexpected feature of mailx treats syntactically valid email addresses as shell commands to execute.

Shell command execution can be re-enabled using the expandaddr option.

Note that this security update does not remove all mailx facilities for command execution, though. Scripts which send mail to addresses obtained from an untrusted source (such as a web form) should use the '--' separator before the email addresses (which was fixed to work properly in this update), or they should be changed to invoke 'mail -t' or 'sendmail -i -t' instead, passing the recipient addresses as part of the mail header.

For the oldstable distribution (squeeze), these problems have been fixed in version 12.4-2+deb6u1.

We recommend that you upgrade your heirloom-mailx packages.");

  script_tag(name:"affected", value:"'heirloom-mailx' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"heirloom-mailx", ver:"12.4-2+deb6u1", rls:"DEB6"))) {
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
