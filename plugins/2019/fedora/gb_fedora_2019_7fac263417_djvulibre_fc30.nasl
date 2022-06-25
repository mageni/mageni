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
  script_oid("1.3.6.1.4.1.25623.1.0.877060");
  script_version("2019-12-06T11:38:15+0000");
  script_cve_id("CVE-2019-18804");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-06 11:38:15 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-04 03:30:47 +0000 (Wed, 04 Dec 2019)");
  script_name("Fedora Update for djvulibre FEDORA-2019-7fac263417");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SWT7E7BMWV5T33AMU6OGDPPTPIGCFFZF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'djvulibre'
  package(s) announced via the FEDORA-2019-7fac263417 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DjVu is a web-centric format and software platform for distributing documents
and images. DjVu can advantageously replace PDF, PS, TIFF, JPEG, and GIF for
distributing scanned documents, digital documents, or high-resolution pictures.
DjVu content downloads faster, displays and renders faster, looks nicer on a
screen, and consume less client resources than competing formats. DjVu images
display instantly and can be smoothly zoomed and panned with no lengthy
re-rendering.

DjVuLibre is a free (GPL&#39, ed) implementation of DjVu, including viewers,
decoders, simple encoders, and utilities. The browser plugin is in its own
separate sub-package.");

  script_tag(name:"affected", value:"'djvulibre' package(s) on Fedora 30.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"djvulibre", rpm:"djvulibre~3.5.27~16.fc30", rls:"FC30"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);