# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.878047");
  script_version("2020-07-09T12:15:58+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-10 11:44:30 +0000 (Fri, 10 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-08 03:19:19 +0000 (Wed, 08 Jul 2020)");
  script_name("Fedora: Security Advisory for gst (FEDORA-2020-3d23d3ea02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-3d23d3ea02");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UHQBAT7JOTIIVV7HBJNCNRMHQYYDSO7R");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gst'
  package(s) announced via the FEDORA-2020-3d23d3ea02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GST is a GTK system utility designed to stress and monitoring various hardware
components like CPU and RAM.

  - Run different CPU and memory stress tests

  - Run multi and single core benchmark

  - Show Processor information (name, cores, threads, family, model, stepping,
  flags, bugs, etc)

  - Show Processor&#39, s cache information

  - Show Motherboard information (vendor, model, bios version, bios date, etc)

  - Show RAM information (size, speed, rank, manufacturer, part number, etc)

  - Show CPU usage (core %, user %, load avg, etc)

  - Show Memory usage

  - Show CPU&#39, s physical&#39, s core clock (current, min, max)

  - Show Hardware monitor (info provided by sys/class/hwmon)");

  script_tag(name:"affected", value:"'gst' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"gst", rpm:"gst~0.7.4~1.fc31", rls:"FC31"))) {
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