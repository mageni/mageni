###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2014-380.nasl 7101 2017-09-12 06:15:03Z asteins$
#
# Amazon Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@iki.fi>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120402");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:25:33 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_name("Amazon Linux Local Check: ALAS-2014-380");
  script_tag(name:"insight", value:"It was reported that Python built-in _json module have a flaw (insufficient bounds checking), which allows a local user to read current process's arbitrary memory.Quoting the upstream bug report:The sole prerequisites of this attack are that the attacker is able to control or influence the two parameters of the default scanstring function: the string to be decoded and the index.The bug is caused by allowing the user to supply a negative index value. The index value is then used directly as an index to an array in the C code. Internally the address of the array and its index are added to each other in order to yield the address of the value that is desired. However, by supplying a negative index value and adding this to the address of the array, the processor's register value wraps around and the calculated value will point to a position in memory which isn't within the bounds of the supplied string, causing the function to access other parts of the process memory.");
  script_tag(name:"solution", value:"Run yum update python27 to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-380.html");
  script_cve_id("CVE-2014-4616");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
  script_copyright("Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"python27-tools", rpm:"python27-tools~2.7.5~13.35.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"python27", rpm:"python27~2.7.5~13.35.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"python27-test", rpm:"python27-test~2.7.5~13.35.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"python27-debuginfo", rpm:"python27-debuginfo~2.7.5~13.35.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"python27-libs", rpm:"python27-libs~2.7.5~13.35.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"python27-devel", rpm:"python27-devel~2.7.5~13.35.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
