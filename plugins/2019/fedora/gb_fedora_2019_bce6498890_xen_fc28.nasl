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
  script_oid("1.3.6.1.4.1.25623.1.0.875528");
  script_version("2019-04-02T06:16:35+0000");
  script_cve_id("CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966",
                "CVE-2018-19967", "CVE-2018-18883", "CVE-2018-3620", "CVE-2018-3646",
                "CVE-2018-15469", "CVE-2018-15468", "CVE-2018-15470", "CVE-2018-12891",
                "CVE-2018-12893", "CVE-2018-12892", "CVE-2018-3665", "CVE-2018-3639",
                "CVE-2018-8897", "CVE-2018-10982", "CVE-2018-10981", "CVE-2018-10472",
                "CVE-2018-10471");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-02 06:16:35 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-28 13:54:39 +0000 (Thu, 28 Mar 2019)");
  script_name("Fedora Update for xen FEDORA-2019-bce6498890");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC28");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UXC6BME7SXJI2ZIATNXCAH7RGPI4UKTT");

  script_tag(name:"summary", value:"The remote host is missing an update for the
  'xen' package(s) announced via the FEDORA-2019-bce6498890 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"This package contains the XenD daemon and
  xm command line tools, needed to manage virtual machines running under the
  Xen hypervisor");

  script_tag(name:"affected", value:"'xen' package(s) on Fedora 28.");

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

if(release == "FC28") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.10.3~2.fc28", rls:"FC28"))) {
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
