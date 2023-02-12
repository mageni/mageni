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
  script_oid("1.3.6.1.4.1.25623.1.0.823139");
  script_version("2023-01-18T10:11:02+0000");
  script_cve_id("CVE-2022-46391");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-18 10:11:02 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 02:03:44 +0000 (Wed, 18 Jan 2023)");
  script_name("Fedora: Security Advisory for awstats (FEDORA-2023-fda5480804)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-fda5480804");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MYUZIFVB4N3NK4WGNHRNXZKJITCJBJX4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'awstats'
  package(s) announced via the FEDORA-2023-fda5480804 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Advanced Web Statistics is a powerful and full-featured tool that generates
advanced web server graphical statistics. This server log analyzer works
from the command line or as a CGI and shows all information your log contains,
in graphical web pages. It can analyze a lot of web/wap/proxy servers such as
Apache, IIS, Weblogic, Webstar, Squid, ... but also mail or FTP servers.

This program can measure visits, unique visitors, authenticated users, pages,
domains/countries, OS busiest times, robot visits, type of files, search
engines/keywords used, visit duration, HTTP errors and more...
Statistics can be updated from a browser or your scheduler.
The program also supports virtual servers, plugins and a lot of features.");

  script_tag(name:"affected", value:"'awstats' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"awstats", rpm:"awstats~7.8~9.fc36", rls:"FC36"))) {
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
