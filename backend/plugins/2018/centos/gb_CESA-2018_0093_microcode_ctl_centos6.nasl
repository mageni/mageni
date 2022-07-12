###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0093_microcode_ctl_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for microcode_ctl CESA-2018:0093 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882827");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-18 07:35:56 +0100 (Thu, 18 Jan 2018)");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for microcode_ctl CESA-2018:0093 centos6");
  script_tag(name:"summary", value:"Check the version of microcode_ctl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The microcode_ctl packages provide
microcode updates for Intel and AMD processors.

This update supersedes microcode provided by Red Hat with the CVE-2017-5715
(Spectre) CPU branch injection vulnerability mitigation. (Historically,
Red Hat has provided updated microcode, developed by our microprocessor
partners, as a customer convenience.) Further testing has uncovered
problems with the microcode provided along with the Spectre mitigation
that could lead to system instabilities. As a result, Red Hat is providing
an microcode update that reverts to the last known good microcode version
dated before 03 January 2018. Red Hat strongly recommends that customers
contact their hardware provider for the latest microcode updates.

IMPORTANT: Customers using Intel Skylake-, Broadwell-, and Haswell-based
platforms must obtain and install updated microcode from their hardware
vendor immediately. The 'Spectre' mitigation requires both an updated
kernel from Red Hat and updated microcode from your hardware vendor.");
  script_tag(name:"affected", value:"microcode_ctl on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-January/022709.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~1.17~25.4.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
