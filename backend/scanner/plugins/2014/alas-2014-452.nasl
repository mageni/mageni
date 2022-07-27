###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2014-452.nasl 7000 2017-08-24 11:51:46Z teissa$
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
  script_oid("1.3.6.1.4.1.25623.1.0.120017");
  script_version("$Revision: 11711 $");
  script_tag(name:"creation_date", value:"2015-09-08 13:15:02 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 14:30:57 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: ALAS-2014-452");
  script_tag(name:"insight", value:"Multiple flaws were found in X11. Please see the references for more information.");
  script_tag(name:"solution", value:"Run yum update libX11 libXcursor libXfixes libXi libXrandr libXrender libXres libXt libXv libXvMC libXxf86dga libXxf86vm libdmx xorg-x11-proto-devel to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-452.html");
  script_cve_id("CVE-2013-2062", "CVE-2013-2064", "CVE-2013-2066", "CVE-2013-2003", "CVE-2013-2002", "CVE-2013-2001", "CVE-2013-2000", "CVE-2013-2005", "CVE-2013-2004", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1995", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-1989", "CVE-2013-1988", "CVE-2013-1987", "CVE-2013-1986", "CVE-2013-1985", "CVE-2013-1984", "CVE-2013-1983", "CVE-2013-1982", "CVE-2013-1981", "CVE-2013-1997");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"libX11-debuginfo", rpm:"libX11-debuginfo~1.6.0~2.2.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libX11", rpm:"libX11~1.6.0~2.2.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libX11-common", rpm:"libX11-common~1.6.0~2.2.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.0~2.2.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXcursor-debuginfo", rpm:"libXcursor-debuginfo~1.1.14~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXcursor", rpm:"libXcursor~1.1.14~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXcursor-devel", rpm:"libXcursor-devel~1.1.14~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXfixes", rpm:"libXfixes~5.0.1~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXfixes-debuginfo", rpm:"libXfixes-debuginfo~5.0.1~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXfixes-devel", rpm:"libXfixes-devel~5.0.1~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXrandr-debuginfo", rpm:"libXrandr-debuginfo~1.4.1~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXrandr", rpm:"libXrandr~1.4.1~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXrandr-devel", rpm:"libXrandr-devel~1.4.1~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXrender", rpm:"libXrender~0.9.8~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXrender-debuginfo", rpm:"libXrender-debuginfo~0.9.8~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXrender-devel", rpm:"libXrender-devel~0.9.8~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXres-debuginfo", rpm:"libXres-debuginfo~1.0.7~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXres", rpm:"libXres~1.0.7~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXres-devel", rpm:"libXres-devel~1.0.7~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXt-devel", rpm:"libXt-devel~1.1.4~6.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXt-debuginfo", rpm:"libXt-debuginfo~1.1.4~6.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXt", rpm:"libXt~1.1.4~6.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXv-devel", rpm:"libXv-devel~1.0.9~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXv-debuginfo", rpm:"libXv-debuginfo~1.0.9~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXv", rpm:"libXv~1.0.9~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXvMC", rpm:"libXvMC~1.0.8~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXvMC-debuginfo", rpm:"libXvMC-debuginfo~1.0.8~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXvMC-devel", rpm:"libXvMC-devel~1.0.8~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXi", rpm:"libXi~1.7.2~2.2.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXi-devel", rpm:"libXi-devel~1.7.2~2.2.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXi-debuginfo", rpm:"libXi-debuginfo~1.7.2~2.2.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXxf86dga", rpm:"libXxf86dga~1.1.4~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXxf86dga-debuginfo", rpm:"libXxf86dga-debuginfo~1.1.4~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXxf86dga-devel", rpm:"libXxf86dga-devel~1.1.4~2.1.8.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXxf86vm-devel", rpm:"libXxf86vm-devel~1.1.3~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXxf86vm-debuginfo", rpm:"libXxf86vm-debuginfo~1.1.3~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXxf86vm", rpm:"libXxf86vm~1.1.3~2.1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libdmx-debuginfo", rpm:"libdmx-debuginfo~1.1.3~3.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libdmx", rpm:"libdmx~1.1.3~3.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"xorg-x11-proto-devel", rpm:"xorg-x11-proto-devel~7.7~9.10.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
