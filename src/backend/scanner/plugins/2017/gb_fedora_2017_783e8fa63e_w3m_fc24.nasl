###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for w3m FEDORA-2017-783e8fa63e
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
  script_oid("1.3.6.1.4.1.25623.1.0.872507");
  script_version("$Revision: 14225 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 15:32:03 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-03-21 05:56:01 +0100 (Tue, 21 Mar 2017)");
  script_cve_id("CVE-2016-9422", "CVE-2016-9423", "CVE-2016-9424", "CVE-2016-9425",
		"CVE-2016-9428", "CVE-2016-9426", "CVE-2016-9429", "CVE-2016-9430",
		"CVE-2016-9431", "CVE-2016-9432", "CVE-2016-9433", "CVE-2016-9434",
		"CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438",
		"CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442",
		"CVE-2016-9443", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624",
		"CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628",
		"CVE-2016-9629", "CVE-2016-9631", "CVE-2016-9630", "CVE-2016-9632",
		"CVE-2016-9633");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for w3m FEDORA-2017-783e8fa63e");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'w3m'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"w3m on Fedora 24");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FPDUQSVEFUS57KVJBROLLBDTK2KJCT4V");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC24");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.3~30.git20170102.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
