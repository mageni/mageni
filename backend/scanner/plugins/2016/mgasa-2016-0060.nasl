###############################################################################
# OpenVAS Vulnerability Test
# $Id: mgasa-2016-0060.nasl 14180 2019-03-14 12:29:16Z cfischer $
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2016 Eero Volotinen, http://www.solinor.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.131219");
  script_version("$Revision: 14180 $");
  script_tag(name:"creation_date", value:"2016-02-11 07:22:18 +0200 (Thu, 11 Feb 2016)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:29:16 +0100 (Thu, 14 Mar 2019) $");
  script_name("Mageia Linux Local Check: mgasa-2016-0060");
  script_tag(name:"insight", value:"Updated ffmpeg packages fix security vulnerabilities: FFmpeg 2.x allows remote attackers to conduct cross-origin attacks and read arbitrary files by using the concat protocol in an HTTP Live Streaming (HLS) M3U8 file, leading to an external HTTP request in which the URL string contains the first line of a local file (CVE-2016-1897). FFmpeg 2.x allows remote attackers to conduct cross-origin attacks and read arbitrary files by using the subfile protocol in an HTTP Live Streaming (HLS) M3U8 file, leading to an external HTTP request in which the URL string contains an arbitrary line of a local file (CVE-2016-1898). Out-of-array read in FFmpeg before 2.4.13 in jpeg2000_decode_tile() in jpeg2000dec.c (CVE-2016-2213).");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0060.html");
  script_cve_id("CVE-2016-1897", "CVE-2016-1898", "CVE-2016-2213");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2016-0060");
  script_copyright("Eero Volotinen");
  script_family("Mageia Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.4.13~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
