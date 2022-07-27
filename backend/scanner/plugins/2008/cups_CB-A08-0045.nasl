# OpenVAS Vulnerability Test
# $Id: cups_CB-A08-0045.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: Cups < 1.3.8 vulnerability
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90017");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)");
  script_cve_id("CVE-2008-1722", "CVE-2008-0047");
  script_bugtraq_id(28781);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Cups < 1.3.8 vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/release");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"All Cups users should upgrade to the latest version:");
  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-1722 CVE-2008-0047.");

  script_tag(name:"impact", value:"CVE-2008-0047: Heap-based buffer overflow in the cgiCompileSearch
  function in CUPS 1.3.5, and other versions including the version bundled with Apple Mac OS X 10.5.2,
  when printer sharing is enabled, allows remote attackers to execute arbitrary code via crafted search
  expressions.

  CVE-2008-1722: Multiple integer overflows in (1) filter/image-png.c and (2) filter/image-zoom.c in CUPS
  1.3 allow attackers to cause a denial of service (crash) and trigger memory corruption, as demonstrated
  via a crafted PNG image.");

  exit(0);
}

include("revisions-lib.inc");
include("version_func.inc");
include("pkg-lib-deb.inc");

kbrls = dpkg_get_ssh_release();
if(!kbrls)
  exit(0);

rls = NULL;
ver = NULL;
rel = NULL;
pkg = NULL;
rls[0] = "SUSE10.0";
ver[0] = "1.2.7";
rel[0] = "12.17";
pkg[0] = "cups";
rls[1] = "SUSE10.1";
ver[1] = "1.2.7";
rel[1] = "12.17";
pkg[1] = "cups";
rls[2] = "SUSE10.2";
ver[2] = "1.2.7";
rel[2] = "12.17";
pkg[2] = "cups";
rls[3] = "SUSE10.3";
ver[3] = "1.2.12";
rel[3] = "22.15";
pkg[3] = "cups";
rls[4] = "SUSE10.0";
ver[4] = "1.2.7";
rel[4] = "12.17";
pkg[4] = "cups-client";
rls[5] = "SUSE10.1";
ver[5] = "1.2.7";
rel[5] = "12.17";
pkg[5] = "cups-client";
rls[6] = "SUSE10.2";
ver[6] = "1.2.7";
rel[6] = "12.17";
pkg[6] = "cups-client";
rls[7] = "SUSE10.3";
ver[7] = "1.2.12";
rel[7] = "22.15";
pkg[7] = "cups-client";
rls[8] = "FC7";
ver[8] = "1.2.12";
rel[8] = "11.fc7";
pkg[8] = "cups";
rls[9] = "FC8";
ver[9] = "1.3.7";
rel[9] = "2.fc8";
pkg[9] = "cups";
rls[10] = "SUSE10.0";
ver[10] = "1.2.7";
rel[10] = "12.13";
pkg[10] = "cups-libs";
rls[11] = "SUSE10.1";
ver[11] = "1.2.7";
rel[11] = "12.17";
pkg[11] = "cups-libs";
rls[12] = "SUSE10.2";
ver[12] = "1.2.7";
rel[12] = "12.17";
pkg[12] = "cups-libs";
rls[13] = "SUSE10.3";
ver[13] = "1.2.12";
rel[13] = "22.15";
pkg[13] = "cups-libs";
rls[14] = "FC9";
ver[14] = "1.3.7";
rel[14] = "2.fc9";
pkg[14] = "cups";

foreach i (keys(rls)) {
  if( kbrls == rls[i] ) {
    rpms = get_kb_item("ssh/login/rpms");
    if( rpms ) {
      pat = ";"+pkg[i]+"~([0-9\.\-]+)";
      version = get_string_version(text:rpms, ver_pattern:pat);
      if(!isnull(version)) {
        if( version_is_less(version:version[1], test_version:ver[i]) ) {
          security_message(port:0);
        } else {
          if( version_is_equal(version:version[1], test_version:ver[i]) ) {
            pat = version[0]+"~([0-9\.\-]+)";
            release = get_string_version(text:rpms, ver_pattern:pat);
            if(!isnull(release)) {
              if( version_is_less(version:release[1] ,test_version:rel[i]) ) {
                security_message(port:0);
              }
            }
          }
        }
      }
    }
  }
}

rls = NULL;
ver = NULL;
rel = NULL;
pkg = NULL;
rls[0] = "GENTOO";
pat = "net-print/cups-([a-zA-Z0-9\.\-]+)";
ver[0] = "1.2.12-r8";
if( kbrls == rls[0] ) {
  pkg = get_kb_item("ssh/login/pkg");
  if(pkg) {
    version = get_string_version(text:pkg, ver_pattern:pat);
    if(!isnull(version)) {
      security_message(port:0);
    }
  }
}

rls = NULL;
ver = NULL;
rel = NULL;
pkg = NULL;
rls[0] = "UBUNTU6.06 LTS";
ver[0] = "1.2.2-0ubuntu0.6.06.9";
pkg[0] = "cupsys";
rls[1] = "UBUNTU6.10";
ver[1] = " 1.2.4-2ubuntu3.4";
pkg[1] = "cupsys";
rls[2] = "UBUNTU7.04";
ver[2] = "1.2.8-0ubuntu8.4";
pkg[2] = "cupsys";
rls[3] = "UBUNTU7.10";
ver[3] = "1.3.2-1ubuntu7.7";
pkg[3] = "cupsys";

foreach i (keys(rls)) {
  if( kbrls == rls[i] ) {
    if(isdpkgvuln(pkg:pkg[i], ver:ver[i], rls:rls[i])) {
      security_message(port:0);
    }
  }
}

exit(0);