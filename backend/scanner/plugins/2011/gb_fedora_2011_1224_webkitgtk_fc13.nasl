###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for webkitgtk FEDORA-2011-1224
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2011-February/054157.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862850");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-02-18 15:15:05 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1407", "CVE-2010-1405", "CVE-2010-1664", "CVE-2010-4040", "CVE-2011-0778", "CVE-2010-4042", "CVE-2010-1421", "CVE-2010-1788", "CVE-2010-1760", "CVE-2010-1422", "CVE-2010-1665", "CVE-2010-2264", "CVE-2010-4493", "CVE-2010-4492", "CVE-2010-2648", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-4198", "CVE-2010-4199", "CVE-2010-1780", "CVE-2010-1771", "CVE-2010-1782", "CVE-2010-1807", "CVE-2010-4197", "CVE-2010-2901", "CVE-2010-1762", "CVE-2010-1386", "CVE-2010-3255", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-1761", "CVE-2010-3259", "CVE-2010-1416", "CVE-2010-1417", "CVE-2010-1418", "CVE-2011-0482", "CVE-2010-1773", "CVE-2010-3257", "CVE-2010-1770", "CVE-2010-1786", "CVE-2010-1759", "CVE-2010-1767", "CVE-2010-3113", "CVE-2010-1787", "CVE-2010-3116", "CVE-2010-3115", "CVE-2010-3114", "CVE-2010-3119", "CVE-2010-1758", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-1812", "CVE-2010-1793", "CVE-2010-1792", "CVE-2010-1791", "CVE-2010-1790", "CVE-2010-4206", "CVE-2010-4204", "CVE-2010-1774", "CVE-2010-1772", "CVE-2010-1392", "CVE-2010-4578");
  script_name("Fedora Update for webkitgtk FEDORA-2011-1224");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC13");
  script_tag(name:"affected", value:"webkitgtk on Fedora 13");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~1.2.7~1.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}