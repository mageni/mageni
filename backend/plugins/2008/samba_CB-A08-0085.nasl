# OpenVAS Vulnerability Test
# $Id: samba_CB-A08-0085.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: Samba 3.0.0 > 3.0.29 vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.90028");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-09-06 20:50:27 +0200 (Sat, 06 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1105");
  script_name("Samba 3.0.0 > 3.0.29 vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/release");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"All Samba users should upgrade to the latest version.");

  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-1105.");

  script_tag(name:"impact", value:"CVE-2008-1105: Heap-based buffer overflow in the receive_smb_raw function
  in util/sock.c in Samba 3.0.0 through 3.0.29 allows remote attackers to execute arbitrary code via a crafted SMB response.");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("pkg-lib-deb.inc");

kbrls = dpkg_get_ssh_release();
if(!kbrls)
  exit(0);

rls = NULL;
ver = NULL;
rel = NULL;
pkg = NULL;
rls[0] = "SUSE10.1";
ver[0] = "3.0.28";
rel[0] = "0.4.3";
pkg[0] = "samba";
rls[1] = "SUSE10.2";
ver[1] = "3.0.23d";
rel[1] = "19.14";
pkg[1] = "samba";
rls[2] = "SUSE10.3";
ver[2] = "3.0.26a";
rel[2] = "3.7";
pkg[2] = "samba";
rls[3] = "FC7";
ver[3] = "3.0.28a";
rel[3] = "1.fc7";
pkg[3] = "samba";
rls[4] = "FC8";
ver[4] = "3.0.30";
rel[4] = "0.fc8";
pkg[4] = "samba";
rls[5] = "FC9";
ver[5] = "3.2.0";
rel[5] = "1.rc1.14.fc9";
pkg[5] = "samba";

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
pat = "net-fs/samba-([a-zA-Z0-9\.\-]+)";
ver[0] = "3.0.28a-r1";
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
ver[0] = "3.0.22-1ubuntu3.7";
pkg[0] = "samba";
rls[1] = "UBUNTU7.04";
ver[1] = "3.0.24-2ubuntu1.6";
pkg[1] = "samba";
rls[2] = "UBUNTU7.10";
ver[2] = "3.0.26a-1ubuntu2.4";
pkg[2] = "samba";
rls[3] = "UBUNTU8.04";
ver[3] = "3.0.28a-1ubuntu4.2";
pkg[3] = "samba";

foreach i (keys(rls)) {
  if( kbrls == rls[i] ) {
    if(isdpkgvuln(pkg:pkg[i], ver:ver[i], rls:rls[i])) {
      security_message(port:0);
    }
  }
}

exit(0);