###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for moodle FEDORA-2014-8609
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.868049");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-08-05 16:40:42 +0530 (Tue, 05 Aug 2014)");
  script_cve_id("CVE-2014-3541", "CVE-2014-3542", "CVE-2014-3543", "CVE-2014-3544",
                "CVE-2014-3545", "CVE-2014-3546", "CVE-2014-3547", "CVE-2014-3548",
                "CVE-2014-3549", "CVE-2014-3550", "CVE-2014-3551", "CVE-2014-3552",
                "CVE-2014-3553", "CVE-2014-0213", "CVE-2014-0214", "CVE-2014-0215",
                "CVE-2014-0216", "CVE-2014-0217", "CVE-2014-0218", "CVE-2014-0122",
                "CVE-2014-0123", "CVE-2014-0124", "CVE-2014-0125", "CVE-2014-0126",
                "CVE-2014-0127", "CVE-2014-0129", "CVE-2014-0008", "CVE-2012-6087");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for moodle FEDORA-2014-8609");
  script_tag(name:"affected", value:"moodle on Fedora 19");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136148.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC19");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.4.11~1.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
