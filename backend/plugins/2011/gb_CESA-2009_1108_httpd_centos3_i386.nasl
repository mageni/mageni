###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2009:1108 centos3 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-June/015973.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880692");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_name("CentOS Update for httpd CESA-2009:1108 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"httpd on CentOS 3");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular Web server. The httpd package shipped
  with Red Hat Enterprise Linux 3 contains an embedded copy of the Apache
  Portable Runtime (APR) utility library, a free library of C data structures
  and routines, which includes interfaces to support XML parsing, LDAP
  connections, database interfaces, URI parsing, and more.

  An off-by-one overflow flaw was found in the way apr-util processed a
  variable list of arguments. An attacker could provide a specially-crafted
  string as input for the formatted output conversion routine, which could,
  on big-endian platforms, potentially lead to the disclosure of sensitive
  information or a denial of service (application crash). (CVE-2009-1956)

  Note: The CVE-2009-1956 flaw only affects big-endian platforms, such as the
  IBM S/390 and PowerPC. It does not affect users using the httpd package on
  little-endian platforms, due to their different organization of byte
  ordering used to represent particular data.

  A denial of service flaw was found in the apr-util Extensible Markup
  Language (XML) parser. A remote attacker could create a specially-crafted
  XML document that would cause excessive memory consumption when processed
  by the XML decoding engine. (CVE-2009-1955)

  A heap-based underwrite flaw was found in the way apr-util created compiled
  forms of particular search patterns. An attacker could formulate a
  specially-crafted search keyword, that would overwrite arbitrary heap
  memory locations when processed by the pattern preparation engine.
  (CVE-2009-0023)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.46~73.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.46~73.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.46~73.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
