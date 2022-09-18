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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2004.14.1");
  script_cve_id("CVE-2004-0888", "CVE-2004-0889");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-14-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-14-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-14-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cupsys, tetex-bin, xpdf' package(s) announced via the USN-14-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Markus Meissner discovered even more integer overflow vulnerabilities
in xpdf, a viewer for PDF files. These integer overflows can
eventually lead to buffer overflows.

The Common UNIX Printing System (CUPS) uses the same code to print PDF
files, tetex-bin uses the code to generate PDF output and process
included PDF files. In any case, these vulnerabilities could be
exploited by an attacker providing a specially crafted PDF file which,
when processed by CUPS, xpdf, or pdflatex, could result in abnormal
program termination or the execution of program code supplied by the
attacker.

In the case of CUPS, this bug could be exploited to gain the privileges of
the CUPS print server (by default, user cupsys).

In the cases of xpdf and pdflatex, this bug could be exploited to gain
the privileges of the user invoking the program.");

  script_tag(name:"affected", value:"'cupsys, tetex-bin, xpdf' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.1.20final+cvs20040330-4ubuntu16.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cupsys-client", ver:"1.1.20final+cvs20040330-4ubuntu16.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.1.20final+cvs20040330-4ubuntu16.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.1.20final+cvs20040330-4ubuntu16.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.1.20final+cvs20040330-4ubuntu16.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.1.20final+cvs20040330-4ubuntu16.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsys2-gnutls10", ver:"1.1.20final+cvs20040330-4ubuntu16.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkpathsea-dev", ver:"2.0.2-21ubuntu0.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkpathsea3", ver:"2.0.2-21ubuntu0.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tetex-bin", ver:"2.0.2-21ubuntu0.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-common", ver:"3.00-8ubuntu1.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.00-8ubuntu1.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.00-8ubuntu1.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf", ver:"3.00-8ubuntu1.2", rls:"UBUNTU4.10"))) {
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
