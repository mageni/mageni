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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3379");
  script_cve_id("CVE-2022-21216", "CVE-2022-21233", "CVE-2022-33196", "CVE-2022-33972", "CVE-2022-38090");
  script_tag(name:"creation_date", value:"2023-04-05 14:13:40 +0000 (Wed, 05 Apr 2023)");
  script_version("2023-04-06T10:08:49+0000");
  script_tag(name:"last_modification", value:"2023-04-06 10:08:49 +0000 (Thu, 06 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 19:42:00 +0000 (Tue, 28 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-3379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3379");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3379");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/intel-microcode");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'intel-microcode' package(s) announced via the DLA-3379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple potential security vulnerabilities in some Intel(r) Processors have been found which may allow information disclosure or may allow escalation of privilege. Intel is releasing firmware updates to mitigate this potential vulnerabilities.

Please pay attention that the fix for CVE-2022-33196 might require a firmware update.

CVE-2022-21216

(INTEL-SA-00700) Insufficient granularity of access control in out-of-band management in some Intel(R) Atom and Intel Xeon Scalable Processors may allow a privileged user to potentially enable escalation of privilege via adjacent network access.

CVE-2022-33196

(INTEL-SA-00738) Incorrect default permissions in some memory controller configurations for some Intel(R) Xeon(R) Processors when using Intel(R) Software Guard Extensions which may allow a privileged user to potentially enable escalation of privilege via local access.

This fix may require a firmware update to be effective on some processors.

CVE-2022-33972

(INTEL-SA-00730) Incorrect calculation in microcode keying mechanism for some 3rd Generation Intel(R) Xeon(R) Scalable Processors may allow a privileged user to potentially enable information disclosure via local acces

CVE-2022-38090

(INTEL-SA-00767) Improper isolation of shared resources in some Intel(R) Processors when using Intel(R) Software Guard Extensions may allow a privileged user to potentially enable information disclosure via local access.

CVE-2022-21233

(INTEL-SA-00657) Improper isolation of shared resources in some Intel(R) Processors may allow a privileged user to potentially enable information disclosure via local access.

For Debian 10 buster, these problems have been fixed in version 3.20230214.1~deb10u1.

We recommend that you upgrade your intel-microcode packages.

For the detailed security status of intel-microcode please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20230214.1~deb10u1", rls:"DEB10"))) {
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
