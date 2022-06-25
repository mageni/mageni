# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.819040");
  script_version("2021-10-28T05:10:56+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-28 05:10:56 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-22 01:12:31 +0000 (Fri, 22 Oct 2021)");
  script_name("Fedora: Security Advisory for watchdog (FEDORA-2021-45b7585d65)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-45b7585d65");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/J5W2UNUV6UGNCHVRZWELPPPBJ444STNM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'watchdog'
  package(s) announced via the FEDORA-2021-45b7585d65 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The watchdog program can be used as a powerful software watchdog daemon
or may be alternately used with a hardware watchdog device such as the
IPMI hardware watchdog driver interface to a resident Baseboard
Management Controller (BMC).  watchdog periodically writes to /dev/watchdog,
the interval between writes to /dev/watchdog is configurable through settings
in the watchdog config file.  This configuration file is also used to
set the watchdog to be used as a hardware watchdog instead of its default
software watchdog operation.  In either case, if the device is open but not
written to within the configured time period, the watchdog timer expiration
will trigger a machine reboot. When operating as a software watchdog, the
ability to reboot will depend on the state of the machine and interrupts.
When operating as a hardware watchdog, the machine will experience a hard
reset (or whatever action was configured to be taken upon watchdog timer
expiration) initiated by the BMC.");

  script_tag(name:"affected", value:"'watchdog' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"watchdog", rpm:"watchdog~5.16~2.fc33", rls:"FC33"))) {
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