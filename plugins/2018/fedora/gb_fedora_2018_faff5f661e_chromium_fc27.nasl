###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_faff5f661e_chromium_fc27.nasl 14223 2019-03-15 13:49:35Z cfischer $
#
# Fedora Update for chromium FEDORA-2018-faff5f661e
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874300");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-28 09:00:16 +0200 (Wed, 28 Mar 2018)");
  script_cve_id("CVE-2017-15396", "CVE-2017-15407", "CVE-2017-15408", "CVE-2017-15409",
                "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15412", "CVE-2017-15413",
                "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15417", "CVE-2017-15418",
                "CVE-2017-15419", "CVE-2017-15420", "CVE-2017-15422", "CVE-2018-6056",
                "CVE-2018-6406", "CVE-2018-6057", "CVE-2018-6058", "CVE-2018-6059",
                "CVE-2018-6060", "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063",
                "CVE-2018-6064", "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067",
                "CVE-2018-6068", "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071",
                "CVE-2018-6083", "CVE-2018-6082", "CVE-2018-6081", "CVE-2018-6080",
                "CVE-2018-6079", "CVE-2018-6078", "CVE-2018-6077", "CVE-2018-6076",
                "CVE-2018-6075", "CVE-2018-6074", "CVE-2018-6073", "CVE-2018-6072",
                "CVE-2017-15427", "CVE-2017-15426", "CVE-2017-15425", "CVE-2017-15424",
                "CVE-2017-15423");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2018-faff5f661e");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"chromium on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XCBSSV5ZSWY3Q4NKEKL22B4MOSHCBKVN");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~65.0.3325.181~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
