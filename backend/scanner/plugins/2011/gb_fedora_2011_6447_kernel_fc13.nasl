###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kernel FEDORA-2011-6447
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
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2011-June/061668.html");
  script_oid("1.3.6.1.4.1.25623.1.0.863292");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:46:35 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1093", "CVE-2011-1079", "CVE-2011-1745", "CVE-2011-1746", "CVE-2010-4165", "CVE-2011-0521", "CVE-2010-4346", "CVE-2010-4649", "CVE-2011-0006", "CVE-2010-4648", "CVE-2010-4650", "CVE-2010-4163", "CVE-2010-4668", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-3874", "CVE-2010-4162", "CVE-2010-4249", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3442", "CVE-2010-4258", "CVE-2010-4169", "CVE-2010-4073", "CVE-2010-4072", "CVE-2010-3880", "CVE-2010-4082", "CVE-2010-3904", "CVE-2010-3432", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3301", "CVE-2010-3067", "CVE-2010-2960", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2524", "CVE-2010-2478", "CVE-2010-2071", "CVE-2011-1182", "CVE-2011-2022", "CVE-2010-3084", "CVE-2011-1013", "CVE-2010-4527");
  script_name("Fedora Update for kernel FEDORA-2011-6447");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC13");
  script_tag(name:"affected", value:"kernel on Fedora 13");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.34.9~69.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}