###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for java-1.6.0-openjdk FEDORA-2011-14638
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
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2011-October/068450.html");
  script_oid("1.3.6.1.4.1.25623.1.0.863588");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552",
                "CVE-2011-3544", "CVE-2011-3521", "CVE-2011-3554", "CVE-2011-3389",
                "CVE-2011-3558", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560",
                "CVE-2011-2513", "CVE-2011-0872", "CVE-2011-0865", "CVE-2011-0815",
                "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0867", "CVE-2011-0869",
                "CVE-2011-0870", "CVE-2011-0868", "CVE-2011-0871", "CVE-2011-0864",
                "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4448",
                "CVE-2010-4450", "CVE-2010-4471", "CVE-2010-4472", "CVE-2011-0706",
                "CVE-2010-4476", "CVE-2011-0025");
  script_name("Fedora Update for java-1.6.0-openjdk FEDORA-2011-14638");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC14");
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Fedora 14");
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

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~55.1.9.10.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
