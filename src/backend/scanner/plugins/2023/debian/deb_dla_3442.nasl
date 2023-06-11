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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3442");
  script_cve_id("CVE-2021-32862");
  script_tag(name:"creation_date", value:"2023-06-05 04:21:35 +0000 (Mon, 05 Jun 2023)");
  script_version("2023-06-05T09:09:07+0000");
  script_tag(name:"last_modification", value:"2023-06-05 09:09:07 +0000 (Mon, 05 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-20 01:34:00 +0000 (Sat, 20 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-3442)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3442");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3442");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nbconvert");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nbconvert' package(s) announced via the DLA-3442 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alvaro Munoz from the GitHub Security Lab discovered sixteen ways to exploit a cross-site scripting vulnerability in nbconvert, a tool and library used to convert notebooks to various other formats via Jinja templates.

When using nbconvert to generate an HTML version of a user-controllable notebook, it is possible to inject arbitrary HTML which may lead to cross-site scripting (XSS) vulnerabilities if these HTML notebooks are served by a web server without tight Content-Security-Policy (e.g., nbviewer).

GHSL-2021-1013: XSS in notebook.metadata.language_info.pygments_lexer,

GHSL-2021-1014: XSS in notebook.metadata.title,

GHSL-2021-1015: XSS in notebook.metadata.widgets,

GHSL-2021-1016: XSS in notebook.cell.metadata.tags,

GHSL-2021-1017: XSS in output data text/html cells,

GHSL-2021-1018: XSS in output data image/svg+xml cells,

GHSL-2021-1019: XSS in notebook.cell.output.svg_filename,

GHSL-2021-1020: XSS in output data text/markdown cells,

GHSL-2021-1021: XSS in output data application/javascript cells,

GHSL-2021-1022: XSS in output.metadata.filenames image/png and image/jpeg,

GHSL-2021-1023: XSS in output data image/png and image/jpeg cells,

GHSL-2021-1024: XSS in output.metadata.width/height image/png and image/jpeg,

GHSL-2021-1025: XSS in output data application/vnd.jupyter.widget-state+json cells,

GHSL-2021-1026: XSS in output data application/vnd.jupyter.widget-view+json cells,

GHSL-2021-1027: XSS in raw cells, and

GHSL-2021-1028: XSS in markdown cells.

Some of these vulnerabilities, namely GHSL-2021-1017, -1020, -1021 and -1028, are actually design decisions where text/html, text/markdown, application/javascript and markdown cells should allow for arbitrary JavaScript code execution. These vulnerabilities are therefore left open by default, but users can now opt-out and strip down all JavaScript elements via a new HTMLExporter option sanitize_html.

For Debian 10 buster, this problem has been fixed in version 5.4-2+deb10u1.

We recommend that you upgrade your nbconvert packages.

For the detailed security status of nbconvert please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nbconvert' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"jupyter-nbconvert", ver:"5.4-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-nbconvert-doc", ver:"5.4-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-nbconvert", ver:"5.4-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-nbconvert", ver:"5.4-2+deb10u1", rls:"DEB10"))) {
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
