###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_1871-01_tcpdump.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for tcpdump RHSA-2017:1871-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871861");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:08 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155",
                "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925",
                "CVE-2016-7926", "CVE-2016-7931", "CVE-2016-7936", "CVE-2016-7973",
                "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930",
                "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935",
                "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940",
                "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984",
                "CVE-2016-7985", "CVE-2016-8575", "CVE-2017-5341", "CVE-2017-5485",
                "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574",
                "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205",
                "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484",
                "CVE-2017-5486");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for tcpdump RHSA-2017:1871-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The tcpdump packages contain the tcpdump
  utility for monitoring network traffic. The tcpdump utility can capture and
  display the packet headers on a particular network interface or on all
  interfaces. The following packages have been upgraded to a later upstream
  version: tcpdump (4.9.0). (BZ#1422473) Security Fix(es): * Multiple out of
  bounds read and integer overflow vulnerabilities were found in tcpdump affecting
  the decoding of various protocols. An attacker could create a crafted pcap file
  or send specially crafted packets to the network segment where tcpdump is
  running in live capture mode (without -w) which could cause it to display
  incorrect data, crash or enter an infinite loop. (CVE-2015-0261, CVE-2015-2153,
  CVE-2015-2154, CVE-2015-2155, CVE-2016-7922, CVE-2016-7923, CVE-2016-7924,
  CVE-2016-7925, CVE-2016-7926, CVE-2016-7927, CVE-2016-7928, CVE-2016-7929,
  CVE-2016-7930, CVE-2016-7931, CVE-2016-7932, CVE-2016-7933, CVE-2016-7934,
  CVE-2016-7935, CVE-2016-7936, CVE-2016-7937, CVE-2016-7938, CVE-2016-7939,
  CVE-2016-7940, CVE-2016-7973, CVE-2016-7974, CVE-2016-7975, CVE-2016-7983,
  CVE-2016-7984, CVE-2016-7985, CVE-2016-7986, CVE-2016-7992, CVE-2016-7993,
  CVE-2016-8574, CVE-2016-8575, CVE-2017-5202, CVE-2017-5203, CVE-2017-5204,
  CVE-2017-5205, CVE-2017-5341, CVE-2017-5342, CVE-2017-5482, CVE-2017-5483,
  CVE-2017-5484, CVE-2017-5485, CVE-2017-5486) Red Hat would like to thank the
  Tcpdump project for reporting CVE-2016-7922, CVE-2016-7923, CVE-2016-7924,
  CVE-2016-7925, CVE-2016-7926, CVE-2016-7927, CVE-2016-7928, CVE-2016-7929,
  CVE-2016-7930, CVE-2016-7931, CVE-2016-7932, CVE-2016-7933, CVE-2016-7934,
  CVE-2016-7935, CVE-2016-7936, CVE-2016-7937, CVE-2016-7938, CVE-2016-7939,
  CVE-2016-7940, CVE-2016-7973, CVE-2016-7974, CVE-2016-7975, CVE-2016-7983,
  CVE-2016-7984, CVE-2016-7985, CVE-2016-7986, CVE-2016-7992, CVE-2016-7993,
  CVE-2016-8574, CVE-2016-8575, CVE-2017-5202, CVE-2017-5203, CVE-2017-5204,
  CVE-2017-5205, CVE-2017-5341, CVE-2017-5342, CVE-2017-5482, CVE-2017-5483,
  CVE-2017-5484, CVE-2017-5485, and CVE-2017-5486. Additional Changes: For
  detailed information on changes in this release, see the Red Hat Enterprise
  Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"tcpdump on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00005.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.0~5.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcpdump-debuginfo", rpm:"tcpdump-debuginfo~4.9.0~5.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
