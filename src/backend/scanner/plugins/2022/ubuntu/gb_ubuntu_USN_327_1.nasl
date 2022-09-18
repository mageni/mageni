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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.327.1");
  script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-327-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-327-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-327-1");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Firefox");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-327-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious URL. (CVE-2006-3113, CVE-2006-3677, CVE-2006-3801,
CVE-2006-3803, CVE-2006-3805, CVE-2006-3806, CVE-2006-3807,
CVE-2006-3809, CVE-2006-3811, CVE-2006-3812)

cross-site scripting vulnerabilities were found in the
XPCNativeWrapper() function and native DOM method handlers. A
malicious web site could exploit these to modify the contents or steal
confidential data (such as passwords) from other opened web pages.
(CVE-2006-3802, CVE-2006-3810)

A bug was found in the script handler for automatic proxy
configuration. A malicious proxy could send scripts which could
execute arbitrary code with the user's privileges. (CVE-2006-3808)

Please see

 [link moved to references]

for technical details of these vulnerabilities.");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.5-0ubuntu6.06", rls:"UBUNTU6.06 LTS"))) {
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
