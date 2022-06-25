###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kernel FEDORA-2013-21822
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.867096");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-12-03 14:41:53 +0530 (Tue, 03 Dec 2013)");
  script_cve_id("CVE-2013-4563", "CVE-2013-4348", "CVE-2013-4470", "CVE-2013-4387",
                "CVE-2013-4345", "CVE-2013-4350", "CVE-2013-4343", "CVE-2013-2888",
                "CVE-2013-2889", "CVE-2013-2891", "CVE-2013-2892", "CVE-2013-2893",
                "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897",
                "CVE-2013-2899", "CVE-2013-0343", "CVE-2013-4254", "CVE-2013-4162",
                "CVE-2013-4163", "CVE-2013-4125", "CVE-2013-2232", "CVE-2013-1059",
                "CVE-2013-2234", "CVE-2013-2164", "CVE-2013-2851", "CVE-2013-2852",
                "CVE-2013-2148", "CVE-2013-2147", "CVE-2013-2140", "CVE-2013-2850",
                "CVE-2013-3228", "CVE-2013-3230", "CVE-2013-3231", "CVE-2013-3232",
                "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3076", "CVE-2013-3223",
                "CVE-2013-3225", "CVE-2013-1979", "CVE-2013-3224", "CVE-2013-3222",
                "CVE-2013-1929", "CVE-2013-1873", "CVE-2013-1796", "CVE-2013-1797",
                "CVE-2013-1798", "CVE-2013-1860", "CVE-2013-0913", "CVE-2013-0914",
                "CVE-2013-1828", "CVE-2013-1792", "CVE-2013-1767", "CVE-2013-1763",
                "CVE-2013-0290", "CVE-2013-0228", "CVE-2013-0190");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for kernel FEDORA-2013-21822");


  script_tag(name:"affected", value:"kernel on Fedora 18");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-November/122913.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC18");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.11.9~100.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
