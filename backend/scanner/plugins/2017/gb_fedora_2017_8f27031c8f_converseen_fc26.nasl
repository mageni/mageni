###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_8f27031c8f_converseen_fc26.nasl 14223 2019-03-15 13:49:35Z cfischer $
#
# Fedora Update for converseen FEDORA-2017-8f27031c8f
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873407");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-09-20 12:25:41 +0200 (Wed, 20 Sep 2017)");
  script_cve_id("CVE-2017-11352", "CVE-2017-9144", "CVE-2017-10995", "CVE-2017-11170",
                "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2017-8352",
                "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9098",
                "CVE-2016-9556", "CVE-2016-9559", "CVE-2016-8707", "CVE-2017-12587",
                "CVE-2017-12433", "CVE-2017-12434", "CVE-2017-12435", "CVE-2017-12640",
                "CVE-2017-12641", "CVE-2017-12642", "CVE-2017-12643", "CVE-2017-12644",
                "CVE-2017-12654", "CVE-2017-12662", "CVE-2017-12663", "CVE-2017-12664",
                "CVE-2017-12665", "CVE-2017-12666", "CVE-2017-12427", "CVE-2017-12428",
                "CVE-2017-12429", "CVE-2017-12430", "CVE-2017-12432", "CVE-2017-12418",
                "CVE-2016-5841", "CVE-2016-5842", "CVE-2016-6491", "CVE-2014-9907",
                "CVE-2015-8957", "CVE-2015-8958", "CVE-2015-8959", "CVE-2016-6823",
                "CVE-2016-7101", "CVE-2016-7513", "CVE-2016-7514", "CVE-2016-7515",
                "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518", "CVE-2016-7519",
                "CVE-2016-7520", "CVE-2016-7521", "CVE-2016-5010", "CVE-2017-12140",
                "CVE-2017-11724", "CVE-2017-11750", "CVE-2017-11751", "CVE-2017-11752",
                "CVE-2017-11753", "CVE-2017-11754", "CVE-2017-11755", "CVE-2017-11644",
                "CVE-2017-11639", "CVE-2017-11640", "CVE-2017-11523", "CVE-2017-11446",
                "CVE-2017-11478", "CVE-2017-11360", "CVE-2017-11188", "CVE-2017-11448",
                "CVE-2017-11447", "CVE-2017-11449", "CVE-2017-11450", "CVE-2017-11141",
                "CVE-2017-10928");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for converseen FEDORA-2017-8f27031c8f");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'converseen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"converseen on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XZWYA5OS5LRRUJQEYK6UL6B5CMNYRGIQ");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"converseen", rpm:"converseen~0.9.7.2~3.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
