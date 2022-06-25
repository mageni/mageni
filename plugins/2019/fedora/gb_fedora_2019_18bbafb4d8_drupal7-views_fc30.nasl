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
  script_oid("1.3.6.1.4.1.25623.1.0.876435");
  script_version("2019-06-04T07:02:10+0000");
  # TODO: No CVE assigned yet.  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-06-04 07:02:10 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-02 02:13:52 +0000 (Sun, 02 Jun 2019)");
  script_name("Fedora Update for drupal7-views FEDORA-2019-18bbafb4d8");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SQGRJK6TLVTD2U6Y5LHQGKTPRQUQTCSP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal7-views'
  package(s) announced via the FEDORA-2019-18bbafb4d8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"You need Views if:

  * You like the default front page view, but you find you want to sort it
  differently.

  * You like the default taxonomy/term view, but you find you want to sort it
  differently, for example, alphabetically.

  * You use /tracker, but you want to restrict it to posts of a certain type.

  * You like the idea of the &#39, article&#39, module, but it doesn&#39, t display articles
  the way you like.

  * You want a way to display a block with the 5 most recent posts of some
  particular type.

  * You want to provide &#39, unread forum posts&#39, .

  * You want a monthly archive similar to the typical Movable Type/Wordpress
  archives that displays a link to the in the form of 'Month, YYYY (X)' where
  X is the number of posts that month, and displays them in a block. The links
  lead to a simple list of posts for that month.

Views can do a lot more than that, but those are some of the obvious uses of
Views.

This package provides the following Drupal 7 modules:

  * views

  * views_ui");

  script_tag(name:"affected", value:"'drupal7-views' package(s) on Fedora 30.");

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

  if(!isnull(res = isrpmvuln(pkg:"drupal7-views", rpm:"drupal7-views~3.23~1.fc30", rls:"FC30"))) {
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
